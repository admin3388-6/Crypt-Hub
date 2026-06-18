import os
import secrets
import subprocess
import uuid
import zipfile
import shutil
import time
import json
import hashlib
import re
import gc
from flask import Flask, render_template, request, send_file, jsonify, after_this_request
from werkzeug.utils import secure_filename

# الاستيراد المتقدم للمكتبات التشفيرية من cryptography و pycryptodome
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from argon2.low_level import hash_secret_raw, Type

from Crypto.Cipher import AES, Salsa20, ChaCha20_Poly1305
from Crypto.Hash import HMAC, SHA3_512
from Crypto.Protocol.SecretSharing import Shamir

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # حد أقصى 100 ميغابايت

TEMP_DIR = "/tmp/fortress_temp"
os.makedirs(TEMP_DIR, exist_ok=True)
BC_JAR_PATH = os.path.join(os.environ.get('HOME', '/home/user'), 'bcprov.jar')

# --- دوال مساعدة لحماية الذاكرة والحد من محاولات الاختراق ---

def wipe_variables(*args):
    """محاولة مسح المتغيرات الحساسة من الذاكرة فوراً وإجبار جامع القمامة على العمل"""
    for arg in args:
        if isinstance(arg, bytearray):
            for i in range(len(arg)):
                arg[i] = 0
    gc.collect()

def check_rate_limit(ip_address):
    """التحقق من حظر عنوان الـ IP لحمايته من هجمات التخمين Brute-Force"""
    ip_hash = hashlib.sha256(ip_address.encode()).hexdigest()
    lockout_file = f"/tmp/rate_limits_{ip_hash}.json"
    if os.path.exists(lockout_file):
        try:
            with open(lockout_file, "r") as lf:
                limit_data = json.load(lf)
            if limit_data.get("locked_until", 0) > time.time():
                return int(limit_data["locked_until"] - time.time())
        except Exception:
            pass
    return 0

def record_failed_attempt(ip_address):
    """تسجيل المحاولات الفاشلة لتفعيل حظر مؤقت (30 دقيقة بعد 5 محاولات)"""
    ip_hash = hashlib.sha256(ip_address.encode()).hexdigest()
    lockout_file = f"/tmp/rate_limits_{ip_hash}.json"
    attempts = 1
    if os.path.exists(lockout_file):
        try:
            with open(lockout_file, "r") as lf:
                limit_data = json.load(lf)
            attempts = limit_data.get("attempts", 0) + 1
        except Exception:
            pass
    locked_until = 0
    if attempts >= 5:
        locked_until = time.time() + 1800  # قفل لـ 30 دقيقة
    try:
        os.makedirs(os.path.dirname(lockout_file), exist_ok=True)
        with open(lockout_file, "w") as lf:
            json.dump({"attempts": attempts, "locked_until": locked_until}, lf)
    except Exception:
        pass
    return attempts, locked_until

def reset_rate_limit(ip_address):
    """إعادة تعيين المحاولات الفاشلة لعنوان الـ IP بعد نجاح العملية"""
    ip_hash = hashlib.sha256(ip_address.encode()).hexdigest()
    lockout_file = f"/tmp/rate_limits_{ip_hash}.json"
    if os.path.exists(lockout_file):
        try:
            os.remove(lockout_file)
        except Exception:
            pass

# --- محرك التشفير الرئيسي (Advanced Cryptographic Engine) ---

def encrypt_file_data(data: bytes, password: str = None, seed: bytes = None, argon_params: dict = None, device_hash: bytes = None) -> bytes:
    master_salt = os.urandom(32)
    
    # 1. إعداد بذرة المفتاح (Key Seed)
    if seed is None:
        if not password:
            raise ValueError("Password or Key Share is required.")
        # تجزئة وتقسيم الملح لتغذية خط التمطيط المسبق (Pre-Stretching)
        pre_salt_scrypt = master_salt[0:16]
        argon2_salt = master_salt[16:32]
        
        # المرحلة الأولى: Scrypt لمنع مزارع كروت الشاشة (Memory-Hard CPU defense)
        stretched_1 = hashlib.scrypt(password.encode('utf-8'), salt=pre_salt_scrypt, n=16384, r=8, p=1, dklen=64)
        
        # المرحلة الثانية: PBKDF2-HMAC-SHA3-512 لتمطيط العبء الحسابي
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA3_512(),
            length=64,
            salt=argon2_salt,
            iterations=10000
        )
        stretched_2 = kdf.derive(stretched_1)
        
        # المرحلة الثالثة: Argon2id لاستخراج البذرة الأساسية
        mem = argon_params.get('memory', 131072)
        iters = argon_params.get('iterations', 10)
        par = argon_params.get('parallelism', 4)
        
        seed = hash_secret_raw(
            secret=stretched_2,
            salt=argon2_salt,
            time_cost=iters,
            memory_cost=mem,
            parallelism=par,
            hash_len=16,
            type=Type.ID
        )
        is_shamir_bytes = b"\x00"
    else:
        is_shamir_bytes = b"\x01"
        mem, iters, par = 0, 0, 0

    # 2. اشتقاق مفاتيح مستقلة لكل طبقة تشفير باستخدام HKDF-SHA3-512
    hkdf = HKDF(
        algorithm=hashes.SHA3_512(),
        length=256,
        salt=master_salt,
        info=b"cascade-key-derivation"
    )
    key_material = hkdf.derive(seed)
    
    chacha_key = key_material[0:32]
    aes_gcm_siv_key = key_material[32:96]  # مفتاح SIV يحتاج لـ 64 بايت
    camellia_key = key_material[96:128]
    aes_cbc_key = key_material[128:160]
    salsa_key = key_material[160:192]
    hmac_key = key_material[192:256]

    # 3. توليد نواقل الحركة والمهيئات (Nonces & IVs)
    salsa_nonce = os.urandom(8)
    aes_cbc_iv = os.urandom(16)
    camellia_iv = os.urandom(16)
    chacha_nonce = os.urandom(24)  # XChaCha20 يتطلب 24 بايت

    # 4. إعداد الحشوة العشوائية لإخفاء الطول الحقيقي ومنع التحليل الإحصائي للبنية
    payload_len = len(data)
    target_pad_len = 16 - (payload_len % 16)
    extra_blocks = secrets.randbelow(8) * 16  # حشوات متغيرة الحجم
    pad_len = target_pad_len + extra_blocks
    padded_plaintext = data + os.urandom(pad_len)

    # 5. خط التشفير المتتالي (Symmetric Cryptographic Cascade Pipeline)
    # الطبقة 1: Salsa20
    cipher_salsa = Salsa20.new(key=salsa_key, nonce=salsa_nonce)
    ct_salsa = cipher_salsa.encrypt(padded_plaintext)

    # الطبقة 2: AES-256-CBC
    cipher_cbc = AES.new(aes_cbc_key, AES.MODE_CBC, iv=aes_cbc_iv)
    ct_cbc = cipher_cbc.encrypt(ct_salsa)

    # الطبقة 3: Camellia-256-CFB (تشفير كتل ياباني عالي القوة والموثوقية عبر مكتبة cryptography)
    cipher_camellia = Cipher(algorithms.Camellia(camellia_key), modes.CFB(camellia_iv), backend=default_backend())
    encryptor_camellia = cipher_camellia.encryptor()
    ct_camellia = encryptor_camellia.update(ct_cbc) + encryptor_camellia.finalize()

    # الطبقة 4: AES-256-GCM-SIV (مقاوم لإساءة استخدام النواقل والتكرار المترابط)
    cipher_siv = AES.new(aes_gcm_siv_key, AES.MODE_SIV)
    ct_siv, tag_siv = cipher_siv.encrypt_and_digest(ct_camellia)

    # الطبقة 5: XChaCha20-Poly1305 (طبقة مصد خارجية فائقة السرعة والقوة التشفيرية)
    cipher_chacha = ChaCha20_Poly1305.new(key=chacha_key, nonce=chacha_nonce)
    ct_chacha, tag_chacha = cipher_chacha.encrypt_and_digest(ct_siv)

    # 6. بناء رأس الملف الآمن بحجم 256 بايت (Secure Header)
    magic_bytes = b"FORTRESS"
    version = b"\x01\x00"
    
    header_data = bytearray()
    header_data.extend(magic_bytes)                               # 8
    header_data.extend(version)                                   # 2
    header_data.extend(is_shamir_bytes)                           # 1
    header_data.extend(mem.to_bytes(4, "big"))                    # 4
    header_data.extend(iters.to_bytes(2, "big"))                  # 2
    header_data.extend(par.to_bytes(2, "big"))                    # 2
    header_data.extend(master_salt)                               # 32
    header_data.extend(salsa_nonce)                               # 8
    header_data.extend(aes_cbc_iv)                                # 16
    header_data.extend(camellia_iv)                               # 16
    header_data.extend(chacha_nonce)                              # 24
    header_data.extend(tag_siv)                                   # 16
    header_data.extend(tag_chacha)                                # 16
    
    timestamp = int(time.time())
    header_data.extend(timestamp.to_bytes(8, "big"))              # 8
    
    dev_hash = device_hash if device_hash else b"\x00" * 32
    header_data.extend(dev_hash)                                  # 32
    
    header_data.extend(payload_len.to_bytes(8, "big"))            # 8
    header_data.extend(pad_len.to_bytes(4, "big"))                # 4
    
    # محاذاة رأس الملف إلى 256 بايت بدقة
    current_len = len(header_data)
    padding_header_len = 256 - current_len
    header_data.extend(b"\x00" * padding_header_len)             # 256
    header_bytes = bytes(header_data)

    # 7. توقيع رأس الملف والبيانات المظلمة (HMAC-SHA3-512) لضمان السلامة المطلقة
    hmac_obj = HMAC.new(hmac_key, digestmod=SHA3_512)
    hmac_obj.update(header_bytes + ct_chacha)
    hmac_tag = hmac_obj.digest()  # 64 بايت

    wipe_variables(padded_plaintext, ct_salsa, ct_cbc, ct_camellia, ct_siv)
    return header_bytes + ct_chacha + hmac_tag


def decrypt_file_data(data: bytes, password: str = None, shares: list = None, device_hash: bytes = None) -> bytes:
    if len(data) < 320:  # 256 (رأس) + 64 (توقيع HMAC)
        raise ValueError("File is corrupted or too short.")
    
    header_bytes = data[0:256]
    hmac_tag = data[-64:]
    encrypted_payload = data[256:-64]

    magic_bytes = header_bytes[0:8]
    if magic_bytes != b"FORTRESS":
        raise ValueError("Invalid file format. Security magic mismatch.")
    
    is_shamir_bytes = header_bytes[10:11]
    is_shamir = (is_shamir_bytes == b"\x01")
    
    mem = int.from_bytes(header_bytes[11:15], "big")
    iters = int.from_bytes(header_bytes[15:17], "big")
    par = int.from_bytes(header_bytes[17:19], "big")
    master_salt = header_bytes[19:51]
    salsa_nonce = header_bytes[51:59]
    aes_cbc_iv = header_bytes[59:75]
    camellia_iv = header_bytes[75:91]
    chacha_nonce = header_bytes[91:115]
    tag_siv = header_bytes[115:131]
    tag_chacha = header_bytes[131:147]
    timestamp = int.from_bytes(header_bytes[147:155], "big")
    stored_dev_hash = header_bytes[155:187]
    payload_len = int.from_bytes(header_bytes[187:195], "big")
    pad_len = int.from_bytes(header_bytes[195:199], "big")

    # 1. إعادة بناء البذرة (Key Seed Construction)
    if is_shamir:
        if not shares or len(shares) < 2:
            raise ValueError("This file requires Shamir key shares to decrypt.")
        try:
            seed = Shamir.combine(shares)
        except Exception as e:
            raise ValueError(f"Failed to combine Shamir shares: {str(e)}")
    else:
        if not password:
            raise ValueError("This file is password protected.")
        pre_salt_scrypt = master_salt[0:16]
        argon2_salt = master_salt[16:32]
        
        # تنفيذ خط التمطيط المماثل بدقة بالغة
        stretched_1 = hashlib.scrypt(password.encode('utf-8'), salt=pre_salt_scrypt, n=16384, r=8, p=1, dklen=64)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA3_512(),
            length=64,
            salt=argon2_salt,
            iterations=10000
        )
        stretched_2 = kdf.derive(stretched_1)
        
        seed = hash_secret_raw(
            secret=stretched_2,
            salt=argon2_salt,
            time_cost=iters,
            memory_cost=mem,
            parallelism=par,
            hash_len=16,
            type=Type.ID
        )

    # 2. اشتقاق مفاتيح الطبقات العكسية
    hkdf = HKDF(
        algorithm=hashes.SHA3_512(),
        length=256,
        salt=master_salt,
        info=b"cascade-key-derivation"
    )
    key_material = hkdf.derive(seed)
    
    chacha_key = key_material[0:32]
    aes_gcm_siv_key = key_material[32:96]
    camellia_key = key_material[96:128]
    aes_cbc_key = key_material[128:160]
    salsa_key = key_material[160:192]
    hmac_key = key_material[192:256]

    # 3. التحقق من سلامة الملف ومكافحة التلاعب (HMAC Validation)
    hmac_obj = HMAC.new(hmac_key, digestmod=SHA3_512)
    hmac_obj.update(header_bytes + encrypted_payload)
    computed_tag = hmac_obj.digest()
    
    if not secrets.compare_digest(computed_tag, hmac_tag):
        raise ValueError("Decryption failed. Incorrect password, tampered file, or corrupted structure.")

    # 4. التحقق من بصمة الجهاز في حال تفعيلها
    if stored_dev_hash != b"\x00" * 32:
        current_dev_hash = device_hash if device_hash else b"\x00" * 32
        if not secrets.compare_digest(stored_dev_hash, current_dev_hash):
            raise ValueError("Decryption blocked. This file is locked to another physical device/browser.")

    # 5. معالجة الفك العكسي للطبقات التشفيرية
    # الطبقة 5: XChaCha20-Poly1305
    cipher_chacha = ChaCha20_Poly1305.new(key=chacha_key, nonce=chacha_nonce)
    ct_siv = cipher_chacha.decrypt_and_verify(encrypted_payload, tag_chacha)

    # الطبقة 4: AES-256-GCM-SIV
    cipher_siv = AES.new(aes_gcm_siv_key, AES.MODE_SIV)
    ct_camellia = cipher_siv.decrypt_and_verify(ct_siv, tag_siv)

    # الطبقة 3: Camellia-256-CFB (معالجة فك التشفير عبر مكتبة cryptography)
    cipher_camellia = Cipher(algorithms.Camellia(camellia_key), modes.CFB(camellia_iv), backend=default_backend())
    decryptor_camellia = cipher_camellia.decryptor()
    ct_cbc = decryptor_camellia.update(ct_camellia) + decryptor_camellia.finalize()

    # الطبقة 2: AES-256-CBC
    cipher_cbc = AES.new(aes_cbc_key, AES.MODE_CBC, iv=aes_cbc_iv)
    ct_salsa = cipher_cbc.decrypt(ct_cbc)

    # الطبقة 1: Salsa20
    cipher_salsa = Salsa20.new(key=salsa_key, nonce=salsa_nonce)
    padded_plaintext = cipher_salsa.decrypt(ct_salsa)

    # إزالة الحشوة العشوائية وقص الملف بطوله الدقيق المسجل داخل الرأس
    final_data = padded_plaintext[:payload_len]
    wipe_variables(padded_plaintext, ct_salsa, ct_cbc, ct_camellia, ct_siv)
    return final_data

# --- مسارات الـ API والـ Web Server ---

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/generate-key', methods=['POST'])
def generate_key():
    try:
        req_id = uuid.uuid4().hex
        work_dir = os.path.join(TEMP_DIR, req_id)
        os.makedirs(work_dir, exist_ok=True)

        alias = request.form.get('alias', 'mykey')
        storepass = request.form.get('storepass', '123456')
        keypass = request.form.get('keypass', storepass)
        validity = request.form.get('validity', '10000')
        keyalg = request.form.get('keyalg', 'RSA')
        keysize = request.form.get('keysize', '2048')
        storetype = request.form.get('storetype', 'PKCS12')
        sigalg = request.form.get('sigalg', 'SHA256withRSA')

        dname = f"CN={request.form.get('cn', 'Unknown')}, OU={request.form.get('ou', 'Unknown')}, O={request.form.get('o', 'Unknown')}, L={request.form.get('l', 'Unknown')}, ST={request.form.get('st', 'Unknown')}, C={request.form.get('c', 'US')}"

        key_filename = f"keystore.{storetype.lower()}"
        key_filepath = os.path.join(work_dir, key_filename)

        command = [
            "keytool", "-genkeypair", "-v",
            "-keystore", key_filepath,
            "-alias", alias, "-keyalg", keyalg, "-keysize", keysize,
            "-sigalg", sigalg, "-validity", validity,
            "-storetype", storetype, "-dname", dname,
            "-storepass", storepass, "-keypass", keypass
        ]

        if storetype in ['BKS', 'BCFKS', 'UBER']:
            command.extend(["-providerclass", "org.bouncycastle.jce.provider.BouncyCastleProvider", "-providerpath", BC_JAR_PATH])

        subprocess.run(command, capture_output=True, text=True, check=True)

        list_cmd = ["keytool", "-list", "-v", "-keystore", key_filepath, "-storepass", storepass]
        if storetype in ['BKS', 'BCFKS', 'UBER']:
            list_cmd.extend(["-providerclass", "org.bouncycastle.jce.provider.BouncyCastleProvider", "-providerpath", BC_JAR_PATH, "-storetype", storetype])
        
        list_result = subprocess.run(list_cmd, capture_output=True, text=True)
        
        info_filepath = os.path.join(work_dir, "fingerprints_and_info.txt")
        with open(info_filepath, "w") as f:
            f.write("=== Keystore Security Fingerprints ===\n")
            f.write("Keep this information safe. These are the unique hashes of your key.\n\n")
            f.write(list_result.stdout)

        zip_filename = f"{alias}_SecureKey.zip"
        zip_filepath = os.path.join(TEMP_DIR, zip_filename)
        with zipfile.ZipFile(zip_filepath, 'w') as zipf:
            zipf.write(key_filepath, arcname=key_filename)
            zipf.write(info_filepath, arcname="fingerprints_and_info.txt")

        @after_this_request
        def cleanup(response):
            try:
                shutil.rmtree(work_dir)
                if os.path.exists(zip_filepath):
                    os.remove(zip_filepath)
            except Exception:
                pass
            return response

        return send_file(zip_filepath, as_attachment=True)

    except Exception as e:
        return jsonify({"error": "Key Generation Failed", "details": str(e)}), 500


@app.route('/crypto', methods=['POST'])
def crypto_tool():
    try:
        action = request.form.get('action')
        file = request.files.get('file')
        
        # 1. فحص جدار الحماية للحد من المحاولات (Rate Limiter Check)
        ip_addr = request.remote_addr
        lockout_time = check_rate_limit(ip_addr)
        if lockout_time > 0:
            return jsonify({
                "error": "Access Temporarily Suspended", 
                "details": f"Too many failed operations. Try again in {lockout_time} seconds."
            }), 429

        if not file:
            return jsonify({"error": "Missing Input", "details": "Please select a valid target file."}), 400

        file_data = file.read()
        if len(file_data) > 100 * 1024 * 1024:
            return jsonify({"error": "Size Violation", "details": "Max limit of 100MB exceeded."}), 400

        req_id = uuid.uuid4().hex
        
        # التقاط بصمة المتصفح إن تم تفعيل الخيار
        bind_device = request.form.get('bind_device') == 'true'
        device_fp = request.form.get('device_fingerprint', '')
        device_hash = None
        if bind_device and device_fp:
            device_hash = hashlib.sha256(device_fp.encode()).digest()

        # 2. فحص العمليات المحددة
        if action == 'encrypt':
            password = request.form.get('password')
            if not password:
                return jsonify({"error": "Input Required", "details": "Master Password cannot be empty."}), 400
            
            # التقاط بارامترات الأداء لـ Argon2id
            argon_mem = int(request.form.get('argon_mem', 131072))
            argon_iter = int(request.form.get('argon_iter', 10))
            argon_par = int(request.form.get('argon_par', 4))
            
            argon_params = {
                'memory': argon_mem,
                'iterations': argon_iter,
                'parallelism': argon_par
            }
            
            encrypted_data = encrypt_file_data(
                data=file_data, 
                password=password, 
                argon_params=argon_params, 
                device_hash=device_hash
            )
            
            out_filename = secure_filename(file.filename) + ".locked"
            out_filepath = os.path.join(TEMP_DIR, f"{req_id}_{out_filename}")
            with open(out_filepath, 'wb') as f:
                f.write(encrypted_data)
                
            wipe_variables(file_data, encrypted_data)
            
            @after_this_request
            def cleanup(response):
                try:
                    if os.path.exists(out_filepath):
                        os.remove(out_filepath)
                except Exception:
                    pass
                return response

            return send_file(out_filepath, as_attachment=True, download_name=out_filename)
            
        elif action == 'decrypt':
            password = request.form.get('password')
            if not password:
                return jsonify({"error": "Input Required", "details": "Password required for decryption."}), 400
            
            try:
                decrypted_data = decrypt_file_data(
                    data=file_data, 
                    password=password, 
                    device_hash=device_hash
                )
                
                # تصفير المحاولات الفاشلة فور النجاح
                reset_rate_limit(ip_addr)
                
                out_filename = file.filename.replace('.locked', '') if file.filename.endswith('.locked') else "decrypted_" + secure_filename(file.filename)
                out_filepath = os.path.join(TEMP_DIR, f"{req_id}_{out_filename}")
                with open(out_filepath, 'wb') as f:
                    f.write(decrypted_data)
                    
                wipe_variables(file_data, decrypted_data)
                
                @after_this_request
                def cleanup(response):
                    try:
                        if os.path.exists(out_filepath):
                            os.remove(out_filepath)
                    except Exception:
                        pass
                    return response

                return send_file(out_filepath, as_attachment=True, download_name=out_filename)
                
            except Exception as dec_err:
                attempts, locked_until = record_failed_attempt(ip_addr)
                details_msg = str(dec_err)
                if locked_until > 0:
                    details_msg += f" Lockout active: 30-minute cooling down period triggered."
                else:
                    details_msg += f" (Attempt {attempts} of 5 before automatic system lockout)"
                return jsonify({"error": "Security Mismatch", "details": details_msg}), 403

        elif action == 'shamir_encrypt':
            # نظام تقسيم المفتاح الفيدرالي عبر خوارزمية شامير
            threshold = int(request.form.get('shamir_k', 2))
            total_shares = int(request.form.get('shamir_n', 3))
            
            if threshold > total_shares:
                return jsonify({"error": "Invalid Setup", "details": "Threshold (K) must be less than or equal to Total Shares (N)."}), 400
            
            # توليد بذرة مفتاح عشوائية بالكامل بقوة 128 بت لتقسيمها
            seed = os.urandom(16)
            raw_shares = Shamir.split(threshold, total_shares, seed)
            
            encrypted_data = encrypt_file_data(
                data=file_data,
                seed=seed,
                device_hash=device_hash
            )
            
            work_dir = os.path.join(TEMP_DIR, req_id)
            os.makedirs(work_dir, exist_ok=True)
            
            locked_filename = secure_filename(file.filename) + ".locked"
            locked_filepath = os.path.join(work_dir, locked_filename)
            with open(locked_filepath, 'wb') as f:
                f.write(encrypted_data)
                
            # حفظ أجزاء المفتاح للمستخدم في ملفات نصية مستقلة
            shares_txt = []
            for idx, share_bytes in raw_shares:
                share_str = f"SHARE-{idx}-{share_bytes.hex()}"
                share_filename = f"FORTRESS_SHARE_{idx}_OF_{total_shares}.txt"
                share_filepath = os.path.join(work_dir, share_filename)
                with open(share_filepath, "w") as sf:
                    sf.write("=== FORTRESS CRYPTO MULTI-KEY SHARE ===\n")
                    sf.write(f"Parameters: Upload at least {threshold} shares of {total_shares} to decrypt.\n")
                    sf.write("Keep this secure key portion confidential.\n\n")
                    sf.write(f"{share_str}\n")
                shares_txt.append((share_filepath, share_filename))
            
            # تجميع الملف المشفر مع المفاتيح في ملف ZIP واحد للتنزيل
            zip_filename = f"{secure_filename(file.filename)}_Secure_Split.zip"
            zip_filepath = os.path.join(TEMP_DIR, zip_filename)
            with zipfile.ZipFile(zip_filepath, 'w') as zipf:
                zipf.write(locked_filepath, arcname=locked_filename)
                for path, name in shares_txt:
                    zipf.write(path, arcname=name)
                    
            wipe_variables(file_data, encrypted_data, seed)
            
            @after_this_request
            def cleanup(response):
                try:
                    shutil.rmtree(work_dir)
                    if os.path.exists(zip_filepath):
                        os.remove(zip_filepath)
                except Exception:
                    pass
                return response

            return send_file(zip_filepath, as_attachment=True, download_name=zip_filename)

        elif action == 'shamir_decrypt':
            shares_text = request.form.get('shamir_shares_text', '')
            pattern = re.compile(r"SHARE-(\d+)-([0-9a-fA-F]+)")
            shares = []
            
            # محاولة جلب المفاتيح الملصقة بالصندوق النصي
            for line in shares_text.split('\n'):
                match = pattern.search(line)
                if match:
                    idx = int(match.group(1))
                    share_bytes = bytes.fromhex(match.group(2))
                    shares.append((idx, share_bytes))
                    
            # محاولة قراءة المفاتيح المرفوعة كملفات نصية
            uploaded_keys = request.files.getlist('share_files')
            for uf in uploaded_keys:
                if uf and uf.filename != '':
                    content = uf.read().decode('utf-8', errors='ignore')
                    for line in content.split('\n'):
                        match = pattern.search(line)
                        if match:
                            idx = int(match.group(1))
                            share_bytes = bytes.fromhex(match.group(2))
                            shares.append((idx, share_bytes))

            # منع تكرار نفس الجزء (ضمان تفرّد مؤشرات شامير)
            unique_shares = {}
            for idx, sb in shares:
                unique_shares[idx] = sb
            shares = [(idx, sb) for idx, sb in unique_shares.items()]

            if len(shares) < 2:
                return jsonify({"error": "Insufficient Shares", "details": "At least 2 unique Fortress key shares are required."}), 400
                
            try:
                decrypted_data = decrypt_file_data(
                    data=file_data,
                    shares=shares,
                    device_hash=device_hash
                )
                
                reset_rate_limit(ip_addr)
                
                out_filename = file.filename.replace('.locked', '') if file.filename.endswith('.locked') else "decrypted_" + secure_filename(file.filename)
                out_filepath = os.path.join(TEMP_DIR, f"{req_id}_{out_filename}")
                with open(out_filepath, 'wb') as f:
                    f.write(decrypted_data)
                    
                wipe_variables(file_data, decrypted_data)
                
                @after_this_request
                def cleanup(response):
                    try:
                        if os.path.exists(out_filepath):
                            os.remove(out_filepath)
                    except Exception:
                        pass
                    return response

                return send_file(out_filepath, as_attachment=True, download_name=out_filename)
                
            except Exception as dec_err:
                attempts, locked_until = record_failed_attempt(ip_addr)
                details_msg = str(dec_err)
                if locked_until > 0:
                    details_msg += f" System Lockout triggered."
                return jsonify({"error": "Decryption Aborted", "details": details_msg}), 403

        else:
            return jsonify({"error": "Bad Action", "details": "The action argument is unrecognized."}), 400

    except Exception as e:
        return jsonify({"error": "Fatal Process Failure", "details": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=7860, debug=False)