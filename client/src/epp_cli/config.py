"""
CLI Configuration

Handles configuration loading and management.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


# Default config locations
DEFAULT_CONFIG_PATHS = [
    Path.home() / ".epp" / "config.yaml",
    Path.home() / ".epp" / "config.yml",
    Path("/etc/epp/config.yaml"),
    Path("epp_config.yaml"),
]


@dataclass
class ServerConfig:
    """EPP server configuration."""
    host: str
    port: int = 700
    timeout: int = 30
    verify_server: bool = True


@dataclass
class CertConfig:
    """Certificate configuration."""
    cert_file: Optional[str] = None
    key_file: Optional[str] = None
    ca_file: Optional[str] = None


@dataclass
class CredentialsConfig:
    """Credentials configuration."""
    client_id: Optional[str] = None
    password: Optional[str] = None


@dataclass
class CLIConfig:
    """Complete CLI configuration."""
    server: ServerConfig
    certs: CertConfig = field(default_factory=CertConfig)
    credentials: CredentialsConfig = field(default_factory=CredentialsConfig)
    profile: str = "default"

    @classmethod
    def from_dict(cls, data: dict, profile: str = "default") -> "CLIConfig":
        """
        Create config from dictionary.

        Args:
            data: Configuration dictionary
            profile: Profile name to use

        Returns:
            CLIConfig instance
        """
        # Get profile-specific config or use root
        if "profiles" in data and profile in data["profiles"]:
            profile_data = data["profiles"][profile]
        else:
            profile_data = data

        # Server config (required)
        server_data = profile_data.get("server", {})
        if not server_data.get("host"):
            raise ValueError("Server host is required in configuration")

        server = ServerConfig(
            host=server_data["host"],
            port=server_data.get("port", 700),
            timeout=server_data.get("timeout", 30),
            verify_server=server_data.get("verify_server", True),
        )

        # Certificate config
        certs_data = profile_data.get("certs", {})
        certs = CertConfig(
            cert_file=_expand_path(certs_data.get("cert_file")),
            key_file=_expand_path(certs_data.get("key_file")),
            ca_file=_expand_path(certs_data.get("ca_file")),
        )

        # Credentials config
        creds_data = profile_data.get("credentials", {})
        credentials = CredentialsConfig(
            client_id=creds_data.get("client_id"),
            password=creds_data.get("password"),
        )

        return cls(
            server=server,
            certs=certs,
            credentials=credentials,
            profile=profile,
        )

    @classmethod
    def from_file(cls, path: Path, profile: str = "default") -> "CLIConfig":
        """
        Load config from YAML file.

        Args:
            path: Path to config file
            profile: Profile name to use

        Returns:
            CLIConfig instance
        """
        with open(path) as f:
            data = yaml.safe_load(f)

        return cls.from_dict(data or {}, profile)

    @classmethod
    def find_and_load(cls, profile: str = "default") -> Optional["CLIConfig"]:
        """
        Find and load config from default locations.

        Args:
            profile: Profile name to use

        Returns:
            CLIConfig instance or None if not found
        """
        for path in DEFAULT_CONFIG_PATHS:
            if path.exists():
                return cls.from_file(path, profile)
        return None


def _expand_path(path: Optional[str]) -> Optional[str]:
    """Expand environment variables and ~ in path."""
    if path is None:
        return None
    return os.path.expandvars(os.path.expanduser(path))


def create_sample_config() -> str:
    """
    Generate sample configuration YAML.

    Returns:
        Sample config as YAML string
    """
    return """# EPP Client Configuration
# Copy to ~/.epp/config.yaml

# Default profile
server:
  host: epp.registry.ae
  port: 700
  timeout: 30
  verify_server: true

certs:
  cert_file: ~/.epp/client.crt
  key_file: ~/.epp/client.key
  ca_file: ~/.epp/ca.crt

credentials:
  client_id: your_registrar_id
  # password: your_password  # Optional, will prompt if not set

# Multiple profiles example
profiles:
  production:
    server:
      host: epp.registry.ae
      port: 700
    certs:
      cert_file: ~/.epp/prod/client.crt
      key_file: ~/.epp/prod/client.key
      ca_file: ~/.epp/prod/ca.crt
    credentials:
      client_id: prod_registrar

  ote:
    server:
      host: epp-ote.registry.ae
      port: 700
    certs:
      cert_file: ~/.epp/ote/client.crt
      key_file: ~/.epp/ote/client.key
      ca_file: ~/.epp/ote/ca.crt
    credentials:
      client_id: ote_registrar
"""
