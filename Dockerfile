FROM python:3.11-slim

# Timezone auf Europa/Berlin setzen (behebt Scheduling-Bug)
ENV TZ=Europe/Berlin
RUN apt-get update && apt-get install -y --no-install-recommends tzdata \
    && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime \
    && echo $TZ > /etc/timezone \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY analyzer.py .
COPY webui.py .
COPY appconfig.py .
COPY unifi_block.py .
EXPOSE 8088
CMD ["python", "analyzer.py"]
