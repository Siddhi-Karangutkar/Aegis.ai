FROM python:3.10-slim

LABEL maintainer="aegis.ai" \
      description="Isolated sandbox for attachment analysis"

# Install system-level dependencies for yara and oletools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libmagic1 \
        file \
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /app

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the worker script
COPY worker.py .

# The file to analyze will be mounted at /sample/attachment
RUN mkdir -p /sample

ENTRYPOINT ["python", "/app/worker.py"]
# Default args: file path and filename (overridden at runtime)
CMD ["/sample/attachment", "unknown_file"]
