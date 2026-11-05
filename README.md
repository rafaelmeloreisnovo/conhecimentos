# RAFAELIA Ω — conhecimentos e falsificadores

**Role:** public schemas expressed as testable contracts, adversarial fixtures,
and explicit uncertainty; not a repository of private device data or claims.

This repository defines `rafaelia.public-proof-envelope/v1`, used by the
RafGitTools Android **Exportar prova local** action. Its inner payload is
`rafaelia.rafgittools.device-evidence/v1`. The envelope stores the exact
`payload_json` UTF-8 string plus its SHA-256 digest. Digest equality detects
later alteration; it is **not a device identity signature**.

## Verify the format safely

```bash
python3 -I -B -m unittest discover -s tests -p 'test_*.py' -v
python3 -I -B scripts/validate_proofs.py
python3 -I -B scripts/validate_proofs.py /private/path/your-reviewed-export.json
```

The last invocation can operate on a privately retained file.
Do **not** publish that file automatically. The directory `proofs/` is
optional and publicly visible; any submission must be explicitly reviewed.

The validator rejects changes to payload bytes, unknown keys, duplicate keys,
PAT-like values, emails, local paths, false attestation fields, invalid states,
and claim inflation. A CI PASS proves structural compliance, **not** real
phone execution, secure origin, correct app build, network authorization, or
complete privacy.

**Android falsifier:** on the same app session, capture state before PAT login,
then capture again immediately after login *without restarting*. Compare
`auth_flag`, `profile_visible`, `repository_count`,
`repository_listing_complete`, and `live_probe`. Repeat after a real
restart. Physical observation and app identity require separate checks.

Related roles: [catalogos](https://github.com/rafaelmeloreisnovo/catalogos)
(public feature registry), [RafGitTools](https://github.com/rafaelmeloreisnovo/RafGitTools)
(Android producer).

`claim_allowed=false` remains the default; `TOKEN_VAZIO != 0`.
