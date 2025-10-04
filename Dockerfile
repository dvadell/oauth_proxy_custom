FROM python:3.11-slim

WORKDIR /app

# Instalar dependencias
COPY requirements.txt .
RUN pip install -v --no-cache-dir -r requirements.txt

# Copiar código de la aplicación
COPY . .

# Set flask app environment variable
ENV FLASK_APP=app.py

# Crear directorio para la base de datos
RUN mkdir -p /data

# Exponer puerto
EXPOSE 5000

# Comando para ejecutar la aplicación
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]