FROM python:3.10-slim

# تثبيت متطلبات النظام الأساسية وجافا لدعم Keystore
RUN apt-get update && \
    apt-get install -y default-jdk wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 user
USER user
ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH

WORKDIR $HOME/app

# تنزيل مكتبة Bouncy Castle المتوافقة
RUN wget https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/1.77/bcprov-jdk18on-1.77.jar -O $HOME/bcprov.jar

COPY --chown=user requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=user . .

RUN mkdir -p /tmp/fortress_temp

EXPOSE 7860

CMD ["gunicorn", "-b", "0.0.0.0:7860", "--workers", "2", "--threads", "4", "--timeout", "180", "app:app"]
