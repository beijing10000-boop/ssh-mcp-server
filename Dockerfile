FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/app/data
WORKDIR /app
RUN groupadd --gid 10001 app && useradd --uid 10001 --gid app --create-home app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY sshmcp ./sshmcp
COPY web ./web
RUN mkdir -p /app/data && chown -R app:app /app/data
USER 10001:10001
EXPOSE 9099
CMD ["uvicorn","sshmcp.main:app","--host","0.0.0.0","--port","9099","--proxy-headers","--no-access-log"]
