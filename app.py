# ==========================================
# Tool Name: Crypt-hub (Advanced Security Suite)
# Author: [SkyData]
# Copyright (c) 2026 [SkyData]
# This code is open-source. Attribution is strictly required!
# ==========================================
import os
import subprocess
import uuid
import zipfile
import shutil
from flask import Flask, render_template, request, send_file, jsonify, after_this_request
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from argon2.low_level import hash_secret_raw, Type

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB Max Limit

TEMP_DIR = os.path.join(os.path.dirname(os.path.abspath(__name__)), 'temp_files')
os.makedirs(TEMP_DIR, exist_ok=True)
BC_JAR_PATH = os.path.join(os.environ.get('HOME', ''), 'bcprov.jar')

# --- Crypto Functions (Quantum-Resistant Cascade) ---
def derive_key(password: str, salt: bytes) -> bytes:
    # Argon2id for extreme resistance against brute-force/quantum attacks
    return hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt,
        time_cost=3, memory_cost=65536, parallelism=4, hash_len=64, type=Type.ID
    )

def encrypt_file_data(data: bytes, password: str) -> bytes:
    salt = os.urandom(16)
    key_material = derive_key(password, salt)
    aes_key, chacha_key = key_material[:32], key_material[32:]
    
    # Layer 1: AES-256-GCM
    aesgcm = AESGCM(aes_key)
    nonce1 = os.urandom(12)
    layer1 = aesgcm.encrypt(nonce1, data, None)
    
    # Layer 2: ChaCha20-Poly1305
    chacha = ChaCha20Poly1305(chacha_key)
    nonce2 = os.urandom(12)
    layer2 = chacha.encrypt(nonce2, layer1, None)
    
    return salt + nonce1 + nonce2 + layer2

def decrypt_file_data(data: bytes, password: str) -> bytes:
    salt, nonce1, nonce2, ciphertext = data[:16], data[16:28], data[28:40], data[40:]
    key_material = derive_key(password, salt)
    aes_key, chacha_key = key_material[:32], key_material[32:]
    
    # Decrypt Layer 2
    chacha = ChaCha20Poly1305(chacha_key)
    layer1 = chacha.decrypt(nonce2, ciphertext, None)
    
    # Decrypt Layer 1
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce1, layer1, None)

# --- Routes ---
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

        # Base Keytool command
        command = [
            "keytool", "-genkeypair", "-v",
            "-keystore", key_filepath,
            "-alias", alias, "-keyalg", keyalg, "-keysize", keysize,
            "-sigalg", sigalg, "-validity", validity,
            "-storetype", storetype, "-dname", dname,
            "-storepass", storepass, "-keypass", keypass
        ]

        # Add Bouncy Castle Provider if needed
        if storetype in ['BKS', 'BCFKS', 'UBER']:
            command.extend(["-providerclass", "org.bouncycastle.jce.provider.BouncyCastleProvider", "-providerpath", BC_JAR_PATH])

        subprocess.run(command, capture_output=True, text=True, check=True)

        # Get Fingerprints (SHA1, SHA256)
        list_cmd = ["keytool", "-list", "-v", "-keystore", key_filepath, "-storepass", storepass]
        if storetype in ['BKS', 'BCFKS', 'UBER']:
            list_cmd.extend(["-providerclass", "org.bouncycastle.jce.provider.BouncyCastleProvider", "-providerpath", BC_JAR_PATH, "-storetype", storetype])
        
        list_result = subprocess.run(list_cmd, capture_output=True, text=True)
        
        info_filepath = os.path.join(work_dir, "fingerprints_and_info.txt")
        with open(info_filepath, "w") as f:
            f.write("=== Keystore Security Fingerprints ===\n")
            f.write("Keep this information safe. These are the unique hashes of your key.\n\n")
            f.write(list_result.stdout)

        # Create ZIP
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
        password = request.form.get('password')
        file = request.files.get('file')

        if not file or not password:
            return jsonify({"error": "File and password are required"}), 400

        file_data = file.read()
        if len(file_data) > 50 * 1024 * 1024:
            return jsonify({"error": "File exceeds 50MB limit"}), 400

        req_id = uuid.uuid4().hex
        
        if action == 'encrypt':
            encrypted_data = encrypt_file_data(file_data, password)
            out_filename = secure_filename(file.filename) + ".locked"
            out_filepath = os.path.join(TEMP_DIR, f"{req_id}_{out_filename}")
            with open(out_filepath, 'wb') as f:
                f.write(encrypted_data)
                
        elif action == 'decrypt':
            try:
                decrypted_data = decrypt_file_data(file_data, password)
                out_filename = file.filename.replace('.locked', '') if file.filename.endswith('.locked') else "decrypted_" + secure_filename(file.filename)
                out_filepath = os.path.join(TEMP_DIR, f"{req_id}_{out_filename}")
                with open(out_filepath, 'wb') as f:
                    f.write(decrypted_data)
            except Exception:
                return jsonify({"error": "Decryption failed. Wrong password or corrupted file."}), 403

        @after_this_request
        def cleanup(response):
            try:
                if os.path.exists(out_filepath):
                    os.remove(out_filepath)
            except Exception:
                pass
            return response

        return send_file(out_filepath, as_attachment=True)

    except Exception as e:
        return jsonify({"error": "Crypto Operation Failed", "details": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=7860, debug=False)
