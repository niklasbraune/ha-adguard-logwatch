ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base:3.21
FROM ${BUILD_FROM}

RUN apk add --no-cache python3

COPY rootfs /
RUN chmod a+x /etc/services.d/adguard-logwatch/run