FROM python:3.12-slim
WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends libzbar0 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --upgrade pip \
    && pip install --only-binary=:all: --prefer-binary -r requirements.txt

COPY app/ ./app/
COPY models/ ./models/

EXPOSE 10000

CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","10000"]
