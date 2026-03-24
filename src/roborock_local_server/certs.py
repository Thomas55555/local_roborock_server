"""Certificate provisioning and renewal helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import logging
import os
from pathlib import Path
import subprocess
from typing import Iterable

from cryptography import x509

from .config import AppConfig, AppPaths


LOG = logging.getLogger("roborock_local_server.certs")
ACME_SH_PATH = Path("/opt/acme.sh/acme.sh")


@dataclass(frozen=True)
class CertificatePaths:
    cert_file: Path
    key_file: Path


class CertificateManager:
    """Owns certificate provisioning for the release stack."""

    def __init__(self, *, config: AppConfig, paths: AppPaths) -> None:
        self.config = config
        self.paths = paths

    @property
    def certificate_paths(self) -> CertificatePaths:
        return CertificatePaths(cert_file=self.paths.cert_file, key_file=self.paths.key_file)

    def ensure_certificate(self) -> bool:
        if self.config.tls.mode == "provided":
            if not self.paths.cert_file.exists():
                raise FileNotFoundError(f"Provided TLS cert not found: {self.paths.cert_file}")
            if not self.paths.key_file.exists():
                raise FileNotFoundError(f"Provided TLS key not found: {self.paths.key_file}")
            return False
        if not self._needs_refresh():
            return False
        self._provision_or_renew()
        return True

    def _needs_refresh(self) -> bool:
        if not self.paths.cert_file.exists() or not self.paths.key_file.exists():
            return True
        try:
            cert = x509.load_pem_x509_certificate(self.paths.cert_file.read_bytes())
        except Exception:
            return True
        deadline = datetime.now(timezone.utc) + timedelta(days=self.config.tls.renew_days_before)
        return cert.not_valid_after_utc <= deadline

    def _read_cloudflare_token(self) -> str:
        token = self.paths.cloudflare_token_file.read_text(encoding="utf-8").strip()
        if not token:
            raise RuntimeError(f"Cloudflare token file is empty: {self.paths.cloudflare_token_file}")
        return token

    def _run_acme(self, args: Iterable[str]) -> None:
        self.paths.acme_dir.mkdir(parents=True, exist_ok=True)
        if not ACME_SH_PATH.exists():
            raise FileNotFoundError(f"acme.sh not found in image at {ACME_SH_PATH}")
        env = dict(os.environ)
        env["CF_Token"] = self._read_cloudflare_token()
        command = [
            str(ACME_SH_PATH),
            *args,
            "--home",
            str(self.paths.acme_dir),
            "--server",
            self.config.tls.acme_server,
        ]
        LOG.info("Running ACME command: %s", " ".join(command))
        result = subprocess.run(
            command,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        if result.stdout.strip():
            LOG.info("ACME output:\n%s", result.stdout.strip())
        if result.returncode != 0:
            raise RuntimeError(f"ACME command failed ({result.returncode}): {' '.join(command)}")

    def _provision_or_renew(self) -> None:
        self.paths.certs_dir.mkdir(parents=True, exist_ok=True)
        base_domain = self.config.tls.base_domain
        self._run_acme(["--register-account", "-m", self.config.tls.email])
        self._run_acme(
            [
                "--issue",
                "--dns",
                "dns_cf",
                "-d",
                base_domain,
                "-d",
                f"*.{base_domain}",
                "--keylength",
                "2048",
            ]
        )
        self._run_acme(
            [
                "--install-cert",
                "-d",
                base_domain,
                "--fullchain-file",
                str(self.paths.cert_file),
                "--key-file",
                str(self.paths.key_file),
            ]
        )
        if not self.paths.cert_file.exists() or not self.paths.key_file.exists():
            raise RuntimeError("ACME completed without writing certificate files")
