FROM python:3.12-alpine

RUN apk add --no-cache bash docker-cli docker-cli-compose

WORKDIR /app/vpn/admin

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY docker-entrypoint.sh /usr/local/bin/vpn-admin-entrypoint
RUN chmod +x /usr/local/bin/vpn-admin-entrypoint

EXPOSE 8088

ENTRYPOINT ["vpn-admin-entrypoint"]
