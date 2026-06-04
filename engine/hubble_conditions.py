from __future__ import annotations

import ipaddress
from typing import Any


KUBERNETES_API_DESTINATIONS = {
    "kube-apiserver",
    "kubernetes",
    "kubernetes.default",
    "kubernetes.default.svc",
    "kubernetes.default.svc.cluster.local",
}


def destination_host(destination: Any) -> str:
    value = str(destination or "").strip()
    if not value:
        return ""

    if value.startswith("[") and "]" in value:
        return value[1 : value.index("]")]

    if value.count(":") == 1:
        host, port = value.rsplit(":", 1)
        if port.isdigit():
            return host

    return value


def is_public_destination(destination: Any) -> bool:
    host = destination_host(destination).rstrip(".").lower()
    if not host or host in KUBERNETES_API_DESTINATIONS:
        return False
    if host.endswith(".svc") or ".svc." in host:
        return False

    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return True
