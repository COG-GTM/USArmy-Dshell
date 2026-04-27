FROM python:3-alpine as builder

COPY . /src

WORKDIR /src

ARG OUI_SRC="http://standards-oui.ieee.org/oui/oui.txt"

ENV VIRTUAL_ENV="/opt/venv"

RUN apk add --no-cache cargo curl g++ gcc rust libpcap-dev libffi-dev \
    && python3 -m venv "${VIRTUAL_ENV}" \
    && curl --location --silent --output "/src/dshell/data/oui.txt" "${OUI_SRC}"

ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

RUN pip install --upgrade pip wheel && pip install .

FROM python:3-alpine

ENV VIRTUAL_ENV="/opt/venv"

COPY --from=builder "${VIRTUAL_ENV}/" "${VIRTUAL_ENV}/"

RUN apk add --no-cache bash libstdc++ libpcap \
    && addgroup -S dshell \
    && adduser  -S -G dshell -h /data dshell

VOLUME ["/data"]

WORKDIR "/data"

ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

USER dshell

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=2 \
    CMD dshell --help > /dev/null 2>&1 || exit 1

ENTRYPOINT ["dshell"]
