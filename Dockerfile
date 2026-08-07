FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN chmod +x dragon
ENV PATH="/app:$PATH"
ENTRYPOINT ["python", "main.py"]
