FROM python:3.12-slim

WORKDIR /app
RUN useradd --create-home --shell /bin/bash appuser
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

USER appuser
ENTRYPOINT ["devguard"]
CMD ["scan", "/workspace"]
