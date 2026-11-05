# pool_manager: builds and retires honeypot pool containers
# (honeypot_eshop_N + honeypot_database_N) on demand through the Docker API.
# Also its own helper image: seeding steps run as short-lived containers of
# this same image, which is why rsync is installed.
FROM python:3.15.1-alpine3.24
RUN apk add --no-cache rsync tar \
 && pip install --no-cache-dir docker==7.2.0 redis==8.1.0
WORKDIR /app
COPY pool_logic.py state_export.py manager.py ./
CMD ["python", "-u", "manager.py"]
