"""
This output module converts plugin output into JSON and indexes it into
an Elasticsearch datastore.

NOTE: This module requires the third-party 'elasticsearch' Python module.

Federal-deployment guidance
---------------------------
By default the client connects over TLS (https) and verifies the server
certificate (STIG V-220634 / NIST SC-8). Override knobs (passed via
``--oargs key=value``):

    host            host[:port]; comma-separated for multi-node cluster
                    (default ``localhost:9200``)
    scheme          ``https`` (default) or ``http``
    insecure        ``true`` to allow plaintext + skip TLS cert verification
                    (NOT for production; emits a runtime warning)
    ca_certs        path to a CA bundle for TLS verification
    api_key         Elasticsearch API key (preferred over basic auth)
    http_auth       ``user:password`` for basic auth
    index           index name (default ``dshell``)
    type            doc type label for legacy ES (default ``alerts``;
                    ignored on ES >= 7 where types are deprecated)

Example::

    decode --output=elasticout \\
        --oargs="host=es.example.mil:9200" \\
        --oargs="scheme=https" \\
        --oargs="api_key=$ES_API_KEY" \\
        --oargs="index=dshellalerts" \\
        -d netflow ~/pcap/example.pcap
"""

import ipaddress
import json
import logging
import warnings

from elasticsearch import Elasticsearch

import dshell.output.jsonout

logger = logging.getLogger(__name__)


def _parse_host(value, default_port):
    """Parse 'host' or 'host:port' into a {host, port} dict accepted by
    Elasticsearch().  Supports comma-separated lists for multi-node clusters.
    """
    nodes = []
    for entry in str(value).split(","):
        entry = entry.strip()
        if not entry:
            continue
        if ":" in entry:
            host, port = entry.rsplit(":", 1)
            try:
                port_int = int(port)
            except ValueError:
                port_int = default_port
        else:
            host, port_int = entry, default_port
        nodes.append({"host": host, "port": port_int})
    return nodes


def _truthy(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _apply_tls_settings(client_kwargs, scheme, insecure, ca_certs, hosts):
    """Configure TLS/plaintext options on the Elasticsearch client kwargs.
    Splits the scheme handling out of __init__ to keep cognitive
    complexity in bounds (Sonar python:S3776).
    """
    if scheme == "https":
        client_kwargs["verify_certs"] = not insecure
        if ca_certs:
            client_kwargs["ca_certs"] = ca_certs
        if insecure:
            warnings.warn(
                "elasticout: insecure=true requested; TLS certificate "
                "verification is DISABLED. Do not use in production "
                "(STIG V-220634 / NIST SC-8).",
                stacklevel=2,
            )
        return
    if scheme == "http":
        if not insecure:
            raise ValueError(
                "elasticout: refusing to connect over plaintext HTTP. "
                "Pass --oargs=\"insecure=true\" to acknowledge the risk "
                "or use scheme=https (STIG V-220634 / NIST SC-8)."
            )
        logger.warning(
            "elasticout: connecting to %s over plaintext HTTP; "
            "data in transit is NOT encrypted.",
            hosts,
        )
        return
    raise ValueError(
        "elasticout: scheme must be 'https' or 'http' (got %r)" % scheme
    )


def _apply_auth_settings(client_kwargs, api_key, http_auth):
    """Configure auth on the Elasticsearch client kwargs."""
    if api_key:
        client_kwargs["api_key"] = api_key
        return
    if not http_auth:
        return
    if ":" in str(http_auth):
        user, pw = str(http_auth).split(":", 1)
        client_kwargs["http_auth"] = (user, pw)
    else:
        client_kwargs["http_auth"] = http_auth


class ElasticOutput(dshell.output.jsonout.JSONOutput):
    """Elasticsearch output module.  Use with ``--output=elasticout``."""

    _DESCRIPTION = "Insert plugin alerts into an Elasticsearch instance (TLS by default)"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs.copy())

        host_value = kwargs.get("host", "localhost")
        default_port = int(kwargs.get("port", 9200))
        scheme = str(kwargs.get("scheme", "https")).lower()
        insecure = _truthy(kwargs.get("insecure", False))

        self.options = {
            "index": kwargs.get("index", "dshell"),
            "type": kwargs.get("type", "alerts"),
            "scheme": scheme,
        }

        hosts = _parse_host(host_value, default_port)
        if not hosts:
            hosts = [{"host": "localhost", "port": default_port}]
        for node in hosts:
            node["scheme"] = scheme

        client_kwargs = {"hosts": hosts}
        _apply_tls_settings(
            client_kwargs, scheme, insecure, kwargs.get("ca_certs"), hosts,
        )
        _apply_auth_settings(
            client_kwargs, kwargs.get("api_key"), kwargs.get("http_auth"),
        )

        self.es = Elasticsearch(**client_kwargs)

    def write(self, *args, **kwargs):
        "Converts alert's keyword args to JSON and indexes it into Elasticsearch datastore."
        if args and "data" not in kwargs:
            kwargs["data"] = self.delimiter.join(map(str, args))

        # Elasticsearch can't handle IPv6 ints; expand to string notation.
        for key in ("dipint", "sipint"):
            kwargs.pop(key, None)
        for key in ("dip", "sip"):
            if key in kwargs:
                try:
                    kwargs[key] = ipaddress.ip_address(kwargs[key]).exploded
                except (TypeError, ValueError):
                    pass

        jsondata = json.dumps(
            kwargs, ensure_ascii=self.ensure_ascii, default=self.json_default
        )

        index_kwargs = {"index": self.options["index"], "body": jsondata}
        # ``doc_type`` was deprecated in ES 7 and removed in ES 8. Pass only
        # when the user has explicitly set it AND the client still accepts it.
        try:
            self.es.index(**index_kwargs, doc_type=self.options["type"])
        except TypeError:
            self.es.index(**index_kwargs)


obj = ElasticOutput
