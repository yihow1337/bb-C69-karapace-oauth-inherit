# [Karapace 6.2.4] REST proxy `rest_authorization` + OAUTHBEARER: Basic credentials authenticate as the service principal

**Program:** Aiven Managed Bug Bounty (Bugcrowd)  
**Asset:** https://github.com/Aiven-Open/karapace  
**Version:** 6.2.4 (`09cba53ffcc961038f608b34f7d00fc2df1d313c`)  
**Severity (researcher):** High  
**CWE:** CWE-863 Incorrect Authorization / CWE-269 Improper Privilege Management  
**CVSS 3.1 (conservative):** AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N → **8.1 High**  
(Requires `rest_authorization=true`, `sasl_mechanism=OAUTHBEARER`, and `sasl_oauth_token` configured.)

## Summary
When Karapace REST proxy runs with `rest_authorization=true` and the service SASL mechanism is `OAUTHBEARER` with a configured `sasl_oauth_token`, a request carrying `Authorization: Basic <user:pass>` causes `get_user_proxy` to build a per-user Kafka client that still uses the **service** OAuth token. The Basic username/password are written into the config but ignored by the OAUTHBEARER client-parameter path. The caller therefore performs Kafka operations as the service principal, defeating the purpose of delegated per-user authorization.

## Root cause
1. `get_auth_config_from_header` for Basic sets `sasl_mechanism` from **service** `config.sasl_mechanism` (so it becomes `OAUTHBEARER`), and returns plain username/password only (no `sasl_oauth_token` key).
2. `get_user_proxy` does `config = self.config.copy()` (retaining service `sasl_oauth_token`), then only overwrites plain fields when `"sasl_oauth_token" not in auth_config` — **never clears** the inherited service token.
3. `get_kafka_client_auth_parameters_from_config` sees `OAUTHBEARER` and builds `SimpleOauthTokenProvider(config.sasl_oauth_token)` → service token.

## Locations (6.2.4)
- `src/karapace/kafka_rest_apis/authentication.py` — `get_auth_config_from_header` Basic branch (~L71–80); `get_kafka_client_auth_parameters_from_config` OAUTHBEARER branch (~L148–153)
- `src/karapace/kafka_rest_apis/__init__.py` — `KafkaRest.get_user_proxy` (~L311–331)

## Steps to reproduce (deterministic, no Kafka required)
1. Use released Karapace **6.2.4** sources (or the copied files under `evidence/`).
2. Run `python3 poc_oauth_inherit.py` (standalone mirror of the exact mutation) — expect `ALL CHECKS PASSED` and VULN line showing SERVICE token used for Basic.
3. Optional: import `evidence/.../authentication.py` and assert Basic → provider token equals service JWT (see `real_module_check.log`).

End-to-end against a live Kafka cluster (optional, authorized lab only): enable REST proxy with `rest_authorization=true`, `sasl_mechanism=OAUTHBEARER`, `sasl_oauth_token=<service>`, ACLs that grant the service broad access and a low-privilege user none; `curl -u attacker:x https://rest/.../topics` succeeds as service.

## Actual vs expected
- **Actual (6.2.4):** Basic → Kafka SASL uses service `sasl_oauth_token`.
- **Expected:** Basic must not authenticate as the service on an OAUTHBEARER cluster; either reject Basic with Bearer challenge, or require caller-supplied Bearer token only.

## Negative controls
- Bearer header → uses caller JWT (not service).
- Service mechanism SCRAM/PLAIN + Basic → uses caller plain credentials (no OAuth inheritance).
- Simulated fix from commit `1aadbea` rejects Basic when mechanism is OAUTHBEARER after clearing inherited token/provider.

## Impact / limitations
- Impact: privilege escalation to the REST proxy’s Kafka service identity; read/write topics the service can access; bypass of per-user ACL delegation that `rest_authorization` is documented to provide.
- Limitations: only when OAUTHBEARER + static `sasl_oauth_token` + `rest_authorization=true`. Deployments using only Bearer client tokens without accepting Basic, or non-OAUTHBEARER mechanisms, are unaffected by this specific path.
- Note: upstream commit `a03b927` (post-`1aadbea`, still unreleased) re-enables Basic→service static token for backward compatibility with a warning — residual risk on current `main` when static token is set.

## Duplicate search
- CVE-2025-61673 / GHSA-vq25-vcrw-gj53: Schema Registry OAuth bypass when **Authorization header missing** in 5.0.0–5.0.1 — **different** fingerprint.
- No public advisory found for REST proxy Basic→service OAUTHBEARER inheritance on 6.2.x (searched 2026-11-02).

## Remediation
- On per-user proxy creation: always clear `sasl_oauth_token` and `_sasl_oauth_token_provider` before applying caller credentials.
- If mechanism is OAUTHBEARER and the caller did not supply a Bearer token, reject with `WWW-Authenticate: Bearer` (as in `1aadbea`).
- Prefer not restoring Basic→service-token fallback (`a03b927`) for security-sensitive deployments.

## Payout expectation (rough)
Aiven Bugcrowd lists up to $25,000. AuthZ bypass to service principal on Kafka REST is plausibly **High**; realistic band often mid-high depending on triage (order-of-magnitude **$1,500–$7,500**), not a guarantee.

## Submission status
**NOT SUBMITTED.** Evidence package prepared for researcher approval only.
