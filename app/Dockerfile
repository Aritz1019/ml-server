# Utiliza una imagen base de Python
FROM python:3.10

# Establece el directorio de trabajo en /app
WORKDIR /app

# Copia el código al contenedor
COPY . /app

# Instala las dependencias del código
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Ejecuta el script cuando se inicie el contenedor
CMD ["python", "-u", "main.py"]