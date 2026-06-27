FROM python:3.11-slim

WORKDIR /app

# System dependencies for scapy/packet capture
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    libnet-dev \
    tcpdump \
    net-tools \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create non-root user (for production; packet capture needs root or capabilities)
# RUN useradd -m ahras && chown -R ahras:ahras /app
# USER ahras

EXPOSE 8000 2222 2121 8081

ENV PYTHONUNBUFFERED=1 \
    AHRAS_HOST=0.0.0.0 \
    AHRAS_PORT=8000

CMD ["python", "main.py"]
