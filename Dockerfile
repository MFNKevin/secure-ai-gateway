# Secure AI Gateway - Etape 10 : conteneurisation de la passerelle (III.7.2).
FROM python:3.14-slim

WORKDIR /app

# build-essential : certaines dependances de Presidio/spaCy (blis, thinc)
# compilent des extensions natives a l'installation.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
