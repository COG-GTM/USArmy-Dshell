FROM python:3.12-alpine AS builder

COPY . /src

WORKDIR /src

ARG OUI_SRC="https://standards-oui.ieee.org/oui/oui.txt"

ENV VIRTUAL_ENV="/opt/venv"

RUN apk add cargo curl g++ gcc rust libpcap-dev libffi-dev \
    && python3 -m venv "${VIRTUAL_ENV}" \
    && curl --location --silent --output "/src/dshell/data/oui.txt" "${OUI_SRC}"

ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

RUN pip install --upgrade pip wheel && pip install .

FROM python:3.12-alpine

ENV VIRTUAL_ENV="/opt/venv"

COPY --from=builder "${VIRTUAL_ENV}/" "${VIRTUAL_ENV}/"

RUN apk add --no-cache bash libstdc++ libpcap

RUN addgroup -S dshell && adduser -S dshell -G dshell

VOLUME ["/data"]

WORKDIR "/data"

ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

USER dshell

HEALTHCHECK --interval=30s --timeout=3s CMD ["dshell-decode", "--version"]

ENTRYPOINT ["dshell"]
