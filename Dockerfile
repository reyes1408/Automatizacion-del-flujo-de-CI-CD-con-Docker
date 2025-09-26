FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .

RUN python -m pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

# Descargar recursos necesarios de NLTK
RUN python -m nltk.downloader punkt

CMD ["python", "-u", "app.py"]
