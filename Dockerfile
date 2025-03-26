FROM ghcr.io/linuxserver/baseimage-alpine:3.20

# set version label
LABEL maintainer="ozpinbeacon"

RUN \
  echo "**** install runtime packages ****" && \
  apk add --no-cache \
    python3 \
	py3-apscheduler \
	py3-requests \
	py3-ldap3

# copy local files
COPY root/ /
