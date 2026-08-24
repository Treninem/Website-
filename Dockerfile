FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /app/data
ENV DATABASE_PATH=/app/data/website.db
EXPOSE 8000
CMD ["uvicorn", "app.site:app", "--host", "0.0.0.0", "--port", "8000"]
