FROM python:3.11-slim

WORKDIR /app

# copier requirements et installer
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# copier ton code + modèles
COPY . .

EXPOSE 5000
CMD ["python", "app.py"]


