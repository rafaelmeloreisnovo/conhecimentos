# Optional public, sanitized evidence envelopes

**Default destination for real Android receipts is PRIVATE Google Drive or a private conversation.**
A verified user may optionally add a carefully reviewed, sanitized
`rafaelia.public-proof-envelope/v1` JSON file here via a draft PR.
The verifier rejects unknown fields, common credential/email/path indicators,
incorrect digest, dishonest attestation fields, and impossible status combinations.

The SHA-256 covers the exact UTF-8 bytes of `payload_json`; it detects alteration
after export but does not establish which device, app, user, or program produced it.
Never upload raw screenshots, logs, tokens or internal repo metadata.

Example usage after reviewing the file locally:
```bash
python3 -I -B scripts/validate_proofs.py private-export.json
```
A PASS_SCOPED verifies format only; DEVICE_ATTESTATION remains TOKEN_VAZIO.
