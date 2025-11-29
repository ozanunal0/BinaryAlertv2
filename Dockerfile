FROM public.ecr.aws/lambda/python:3.12

# 1. Sistem paketlerini kur
# unzip: dependencies.zip dosyasını açmak için eklendi
RUN dnf update -y && \
    dnf install -y \
    poppler-utils \
    gcc \
    make \
    tar \
    gzip \
    openssl-devel \
    xz \
    unzip \
    && dnf clean all

# 2. UPX'i (AMD64/x86) manuel indir ve kur
# Not: Mimarimiz x86 olduğu için linki 'amd64' olarak güncelledik.
RUN curl -L -o upx.tar.xz https://github.com/upx/upx/releases/download/v4.2.2/upx-4.2.2-amd64_linux.tar.xz && \
    tar -xf upx.tar.xz && \
    mv upx-4.2.2-amd64_linux/upx /usr/bin/upx && \
    chmod +x /usr/bin/upx && \
    rm -rf upx.tar.xz upx-4.2.2-amd64_linux

# 3. Yextend Kurulumu (Legacy Binary) [YENİ ADIM]
# dependencies.zip dosyasını kopyala ve aç
COPY lambda_functions/analyzer/dependencies.zip /tmp/
RUN unzip /tmp/dependencies.zip -d /tmp/deps && \
    # Binary dosyasını sistem yoluna taşı
    mv /tmp/deps/yextend /usr/bin/yextend && \
    chmod +x /usr/bin/yextend && \
    # Gerekli shared library dosyalarını (varsa) lib dizinine taşı
    (cp /tmp/deps/*.so* /usr/lib64/ || true) && \
    rm -rf /tmp/deps /tmp/dependencies.zip

# 4. Bağımlılıkları kopyala
COPY requirements.txt ./

# 5. Python bağımlılıklarını kur
RUN pip install --no-cache-dir -r requirements.txt

# 6. Uygulama kodlarını ve kuralları kopyala
COPY lambda_functions/analyzer/ ${LAMBDA_TASK_ROOT}/lambda_functions/analyzer/
COPY rules/ ${LAMBDA_TASK_ROOT}/rules/

# 7. YARA kurallarını derle
RUN python3 -c "import yara, glob, os; \
    rules_dir = '/var/task/rules'; \
    yara_files = glob.glob(os.path.join(rules_dir, '**/*.yara'), recursive=True); \
    print(f'Derlenen Kural Sayisi: {len(yara_files)}'); \
    rules = yara.compile(filepaths={os.path.basename(f): f for f in yara_files}); \
    rules.save(os.path.join(rules_dir, 'compiled_yara_rules.bin'))"

# 8. Lambda Handler
CMD [ "lambda_functions.analyzer.main.analyze_lambda_handler" ]