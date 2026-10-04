FROM python:3.12-slim

WORKDIR /app

# Dépendances système
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copier les requirements
COPY requirements.txt .

# Installer les dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# Copier le code
COPY server.py .
COPY whitelist.json .
COPY .env .

# Exposer le port
EXPOSE 8000

# Lancer le serveur MCP
CMD ["python", "server.py"]
