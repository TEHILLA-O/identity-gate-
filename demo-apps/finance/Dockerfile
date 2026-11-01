FROM python:3.12.8-slim
WORKDIR /srv
COPY policy /srv/policy
COPY data /srv/data
COPY demo-apps/common /srv/common
COPY demo-apps/finance /srv/finance
RUN pip install --no-cache-dir fastapi==0.115.6 uvicorn==0.34.0 httpx==0.28.1 PyJWT==2.10.1 cryptography==44.0.0 itsdangerous==2.2.0
ENV PYTHONPATH=/srv
WORKDIR /srv/finance
EXPOSE 8101
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8101"]
