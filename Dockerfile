FROM python:3-alpine AS builder

COPY . /src

WORKDIR /src

# Use HTTPS for the IEEE OUI database (STIG V-220634 / NIST SC-8).
ARG OUI_SRC="https://standards-oui.ieee.org/oui/oui.txt"

ENV VIRTUAL_ENV="/opt/venv"

RUN apk add --no-cache cargo curl g++ gcc rust libpcap-dev libffi-dev \
    && python3 -m venv "${VIRTUAL_ENV}" \
    && curl --fail --location --silent --show-error --output "/src/dshell/data/oui.txt" "${OUI_SRC}"

ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

RUN pip install --upgrade pip wheel && pip install .

FROM python:3-alpine

ENV VIRTUAL_ENV="/opt/venv"

COPY --from=builder "${VIRTUAL_ENV}/" "${VIRTUAL_ENV}/"

# STIG V-220629 / NIST AC-6: drop root in the runtime stage.
RUN apk add --no-cache bash libstdc++ libpcap \
    && addgroup -S dshell \
    && adduser -S -G dshell -h /home/dshell dshell \
    && mkdir -p /data \
    && chown -R dshell:dshell /data /opt/venv

VOLUME ["/data"]

WORKDIR "/data"

ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

USER dshell

ENTRYPOINT ["dshell"]
