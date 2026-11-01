FROM python:3.12.8-slim
WORKDIR /srv
COPY scim-target /srv/scim-target
RUN pip install --no-cache-dir fastapi==0.115.6 uvicorn==0.34.0 sqlalchemy==2.0.36
WORKDIR /srv/scim-target
EXPOSE 8103
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8103"]
