FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY app ./app
RUN groupadd --gid 10001 portal \
    && useradd --uid 10001 --gid portal --create-home portal \
    && pip install --no-cache-dir . \
    && chmod -R a+rX /app \
    && mkdir -p /var/lib/security-portal \
    && chown -R portal:portal /var/lib/security-portal
USER 10001:10001
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000"]
