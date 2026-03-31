FROM python:3-alpine as builder

# Security: Copy only necessary files instead of entire repo (SonarQube S6470)
COPY setup.py /src/setup.py
COPY dshell/ /src/dshell/
COPY README.md /src/README.md
COPY LICENSE /src/LICENSE

WORKDIR /src

ARG OUI_SRC="http://standards-oui.ieee.org/oui/oui.txt"

ENV VIRTUAL_ENV="/opt/venv"

RUN apk add cargo curl g++ gcc rust libpcap-dev libffi-dev \
    && python3 -m venv "${VIRTUAL_ENV}" \
    && curl --location --silent --output "/src/dshell/data/oui.txt" "${OUI_SRC}"

ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

RUN pip install --upgrade pip wheel && pip install .

FROM python:3-alpine

ENV VIRTUAL_ENV="/opt/venv"

COPY --from=builder "${VIRTUAL_ENV}/" "${VIRTUAL_ENV}/"

RUN apk add --no-cache bash libstdc++ libpcap

# Security: Create non-root user to run container (SonarQube S6471, STIG V-220629)
RUN addgroup -S dshell && adduser -S dshell -G dshell

VOLUME ["/data"]

WORKDIR "/data"

# Ensure the non-root user can access the data volume
RUN chown dshell:dshell /data

ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

USER dshell

ENTRYPOINT ["dshell"]
