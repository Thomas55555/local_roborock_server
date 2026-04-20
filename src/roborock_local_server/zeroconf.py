"""mDNS/Zeroconf service announcements for local stack discovery."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket


_LOGGER = logging.getLogger(__name__)
_SERVICE_TYPE = "_roborock-local._tcp.local."


def _sanitize_instance_name(name: str) -> str:
    sanitized = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in name.strip().lower())
    return sanitized.strip("-_") or "roborock-local-server"


def _candidate_ipv4_addresses(*, bind_host: str, stack_fqdn: str) -> list[str]:
    candidates: list[str] = []
    if bind_host and bind_host not in {"0.0.0.0", "::"}:
        candidates.append(bind_host)
    for host in (stack_fqdn, socket.gethostname()):
        if not host:
            continue
        try:
            for family, *_rest, sockaddr in socket.getaddrinfo(host, None, family=socket.AF_INET):
                if family != socket.AF_INET:
                    continue
                address = str(sockaddr[0]).strip()
                if address:
                    candidates.append(address)
        except OSError:
            continue
    deduped: list[str] = []
    for candidate in candidates:
        try:
            parsed = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if parsed.version != 4:
            continue
        if parsed.is_loopback:
            continue
        text = str(parsed)
        if text not in deduped:
            deduped.append(text)
    return deduped


class ZeroconfAnnouncements:
    """Register/unregister zeroconf service announcements for this stack."""

    def __init__(
        self,
        *,
        stack_fqdn: str,
        bind_host: str,
        https_port: int,
        mqtt_tls_port: int,
        region: str,
    ) -> None:
        self._stack_fqdn = stack_fqdn
        self._bind_host = bind_host
        self._https_port = int(https_port)
        self._mqtt_tls_port = int(mqtt_tls_port)
        self._region = region
        self._azc = None
        self._service_info = None

    async def start(self) -> None:
        try:
            from zeroconf import ServiceInfo
            from zeroconf.asyncio import AsyncZeroconf
        except ImportError:
            _LOGGER.info("zeroconf dependency not installed; skipping mDNS announcements")
            return

        addresses = [
            ipaddress.ip_address(addr).packed
            for addr in _candidate_ipv4_addresses(bind_host=self._bind_host, stack_fqdn=self._stack_fqdn)
        ]
        if not addresses:
            _LOGGER.info("No non-loopback IPv4 addresses found; skipping mDNS announcements")
            return

        instance = _sanitize_instance_name(self._stack_fqdn)
        service_name = f"{instance}.{_SERVICE_TYPE}"
        txt_records: dict[str, str] = {
            "instance": instance,
            "stack_fqdn": self._stack_fqdn,
            "region": self._region,
            "https_port": str(self._https_port),
            "mqtt_tls_port": str(self._mqtt_tls_port),
        }

        self._service_info = ServiceInfo(
            type_=_SERVICE_TYPE,
            name=service_name,
            addresses=addresses,
            port=self._https_port,
            properties=txt_records,
            server=f"{instance}.local.",
        )
        self._azc = AsyncZeroconf()
        await self._azc.async_register_service(self._service_info)
        _LOGGER.info(
            "Registered mDNS service %s addresses=%s https=%d mqtt_tls=%d",
            service_name,
            ",".join(str(ipaddress.ip_address(addr)) for addr in addresses),
            self._https_port,
            self._mqtt_tls_port,
        )

    async def stop(self) -> None:
        if self._azc is None or self._service_info is None:
            return
        try:
            await self._azc.async_unregister_service(self._service_info)
        finally:
            await self._azc.async_close()
            self._azc = None
            self._service_info = None

    async def restart(self) -> None:
        await self.stop()
        await self.start()


async def stop_zeroconf_task(task: asyncio.Task[None] | None) -> None:
    if task is None:
        return
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
