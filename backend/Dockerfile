FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY backend/requirements.txt /tmp/requirements.txt
RUN python -m pip install --no-cache-dir -r /tmp/requirements.txt

COPY backend /app/backend
COPY ml/models/threatlens_baseline_model.joblib /app/ml/models/threatlens_baseline_model.joblib
COPY pytest.ini /app/pytest.ini

RUN mkdir -p /app/data \
    && test -f /app/ml/models/threatlens_baseline_model.joblib

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
