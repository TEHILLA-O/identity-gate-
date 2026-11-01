FROM python:3.12.8-slim
WORKDIR /srv
COPY backend /srv/backend
COPY policy /srv/policy
COPY data /srv/data
RUN pip install --no-cache-dir /srv/backend
WORKDIR /srv/backend
ENV PYTHONPATH=/srv/backend:/srv
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
