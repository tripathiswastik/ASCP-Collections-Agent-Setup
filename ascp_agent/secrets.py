"""Secrets and Token Management Engine for ASCP Diagnostic Agent.
Supports:
- Dynamic secret loading & token rotation without process restarts
- File-based secret providers with auto-refresh on modification
- Environment-based secret providers
- Interface for HashiCorp Vault / AWS Secrets Manager / Azure Key Vault
"""

import os
import json
import time
import logging
from typing import Dict, Optional, Any
from abc import ABC, abstractmethod


class SecretProvider(ABC):
    """Abstract Base Class for secret providers."""

    @abstractmethod
    def get_secret(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Fetch a single secret by key."""
        pass

    @abstractmethod
    def get_operator_tokens(self) -> Dict[str, str]:
        """Fetch dictionary of valid API tokens mapping token -> operator_name."""
        pass

    @abstractmethod
    def reload_if_changed(self) -> bool:
        """Trigger reload if secret source has changed or rotated."""
        pass


class EnvSecretProvider(SecretProvider):
    """Loads secrets and operator tokens from environment variables."""

    def __init__(self, token_env_var: str = "ASCP_OPERATOR_TOKENS"):
        self.token_env_var = token_env_var

    def get_secret(self, key: str, default: Optional[str] = None) -> Optional[str]:
        return os.environ.get(key, default)

    def get_operator_tokens(self) -> Dict[str, str]:
        raw = os.environ.get(self.token_env_var, "{}")
        try:
            tokens = json.loads(raw)
            if isinstance(tokens, dict):
                return tokens
        except Exception as exc:
            logging.warning("Failed to parse %s from env: %s", self.token_env_var, exc)
        return {}

    def reload_if_changed(self) -> bool:
        return False


class RotatingFileSecretProvider(SecretProvider):
    """Watches a secure JSON secret file with automatic rotation upon file modification.
    Allows DBAs and DevOps to rotate tokens and credentials on disk with zero downtime.
    """

    def __init__(self, filepath: str, refresh_ttl_seconds: float = 30.0):
        self.filepath = filepath
        self.refresh_ttl_seconds = refresh_ttl_seconds
        self._last_checked: float = 0.0
        self._last_mtime: float = 0.0
        self._cached_secrets: Dict[str, Any] = {}
        self._cached_tokens: Dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        if not os.path.isfile(self.filepath):
            return
        try:
            mtime = os.path.getmtime(self.filepath)
            with open(self.filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                self._cached_secrets = data
                # Extract tokens
                tokens = data.get("operator_tokens", {})
                if isinstance(tokens, dict):
                    self._cached_tokens = tokens
                self._last_mtime = mtime
                self._last_checked = time.time()
                logging.info("[RotatingSecretProvider] Loaded secrets from %s (mtime=%s)", self.filepath, mtime)
        except Exception as exc:
            logging.error("[RotatingSecretProvider] Error loading secrets from %s: %s", self.filepath, exc)

    def reload_if_changed(self) -> bool:
        now = time.time()
        if now - self._last_checked < self.refresh_ttl_seconds:
            return False
        self._last_checked = now
        if not os.path.isfile(self.filepath):
            return False
        try:
            mtime = os.path.getmtime(self.filepath)
            if mtime > self._last_mtime:
                self._load()
                return True
        except Exception as exc:
            logging.warning("[RotatingSecretProvider] Check failed: %s", exc)
        return False

    def get_secret(self, key: str, default: Optional[str] = None) -> Optional[str]:
        self.reload_if_changed()
        return self._cached_secrets.get(key, default)

    def get_operator_tokens(self) -> Dict[str, str]:
        self.reload_if_changed()
        return dict(self._cached_tokens)


class SecretManager:
    """Composite secret manager coordinating primary and fallback providers with rotation support."""

    def __init__(self, primary_provider: Optional[SecretProvider] = None):
        self.providers: list[SecretProvider] = []
        # Check if secrets file is designated
        secret_file = os.environ.get("ASCP_SECRETS_FILE")
        if secret_file and os.path.isfile(secret_file):
            self.providers.append(RotatingFileSecretProvider(secret_file))
        if primary_provider:
            self.providers.append(primary_provider)
        # Default env provider
        self.providers.append(EnvSecretProvider())

    def add_provider(self, provider: SecretProvider) -> None:
        self.providers.insert(0, provider)

    def get_secret(self, key: str, default: Optional[str] = None) -> Optional[str]:
        for provider in self.providers:
            val = provider.get_secret(key)
            if val is not None:
                return val
        return default

    def get_operator_tokens(self) -> Dict[str, str]:
        """Aggregate tokens across all configured providers."""
        tokens: Dict[str, str] = {}
        for provider in reversed(self.providers):
            tokens.update(provider.get_operator_tokens())
        return tokens

    def rotate_tokens(self, new_tokens: Dict[str, str]) -> None:
        """Dynamically inject rotated tokens (useful for automated CI/CD and testing)."""
        class InjectedProvider(SecretProvider):
            def __init__(self, t: Dict[str, str]):
                self.t = t
            def get_secret(self, key: str, default: Optional[str] = None):
                return None
            def get_operator_tokens(self) -> Dict[str, str]:
                return self.t
            def reload_if_changed(self) -> bool:
                return False
        self.add_provider(InjectedProvider(new_tokens))


# Global Secret Manager instance
GLOBAL_SECRET_MANAGER = SecretManager()
