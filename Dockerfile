# Dockerfile seguro para aislar la ejecución de User-Scanner
FROM python:3.11-slim

# Prevenir escritura de bytecode y habilitar buffer limpio
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Crear usuario sin privilegios por seguridad
RUN groupadd -g 1001 appgroup && \
    useradd -u 1001 -g appgroup -m appuser

WORKDIR /app

# Instalar dependencias
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar scripts
COPY secure_runner.py .

# Crear directorio de resultados con permisos adecuados
RUN mkdir -p /app/results && chown -R appuser:appgroup /app

# Cambiar a usuario no-root
USER appuser

ENTRYPOINT ["python", "secure_runner.py"]
CMD ["--help"]
