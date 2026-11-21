# backend/Dockerfile
FROM python:3.10-slim

WORKDIR /app

# Bagimliliklari kopyala ve yukle (cache avantaji icin once bu adim)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Kaynak kodlari kopyala
COPY . .

# FastAPI'yi calistir
CMD ["uvicorn", "backend.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
