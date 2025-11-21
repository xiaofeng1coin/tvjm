FROM python:3.9-alpine as builder

WORKDIR /usr/src/app

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
RUN pip install --upgrade pip

COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /usr/src/app/wheels -r requirements.txt

FROM python:3.9-alpine

WORKDIR /home/appuser/app

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

COPY --from=builder /usr/src/app/wheels /wheels
COPY --from=builder /usr/src/app/requirements.txt .

RUN pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.txt

USER appuser

COPY --chown=appuser:appgroup . .

EXPOSE 5000

CMD ["python", "app.py"]
