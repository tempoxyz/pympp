# Build from the repository root: the image installs pympp from this checkout.
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1
COPY pyproject.toml README.md /pympp/
COPY src /pympp/src
RUN pip install --no-cache-dir "/pympp[tempo,server,sqlite]" starlette uvicorn
WORKDIR /app
COPY examples/session-metered-api/*.py ./
