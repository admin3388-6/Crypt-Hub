FROM python:3.10-slim

# تثبيت Java و wget
RUN apt-get update && \
    apt-get install -y default-jdk wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 user
USER user
ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH

WORKDIR $HOME/app

# تحميل مكتبة Bouncy Castle لدعم صيغ BKS و BCFKS
RUN wget https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/1.77/bcprov-jdk18on-1.77.jar -O $HOME/bcprov.jar

COPY --chown=user requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=user . .

RUN mkdir -p $HOME/app/temp_files

EXPOSE 7860

CMD ["gunicorn", "-b", "0.0.0.0:7860", "--workers", "4", "--threads", "2", "--timeout", "120", "app:app"]
