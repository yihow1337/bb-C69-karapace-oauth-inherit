# Versions / digests

- Program: Aiven Managed Bug Bounty (Bugcrowd `aiven-mbb-og`) — public, paid ($50–$25,000)
- Asset: https://github.com/Aiven-Open (Karapace: https://github.com/Aiven-Open/karapace)
- Vulnerable release tag: **6.2.4**
- Commit: `09cba53ffcc961038f608b34f7d00fc2df1d313c`
- Silent-fix (not in any release tag as of 2026-11-02 Asia/Taipei):
  - `1aadbeadba3aab5febdf3677773c33d2f62f91d9` — “Never let a per-user REST proxy inherit the service OAuth credentials”
  - Follow-up soft-compat `a03b927c95b982d6c9e53066bb66c174636c613d` still allows Basic→service static token when `sasl_oauth_token` is set (warn-only)
- Evidence source files extracted from tag 6.2.4 into `evidence/`
