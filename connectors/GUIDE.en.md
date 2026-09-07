# Connectors
Each product directory has mock and real adapters. Real adapters read endpoints,
tokens, API paths, JSON roots, timeouts, and TLS behavior from environment
variables only. No connector prints token values.

QRadar sender supports dry-run JSON syslog and LEEF payload generation.

## Real connector runner
```bash
python connectors/run.py vault --limit 20
python connectors/run.py boundary --qradar-host "$QRADAR_SYSLOG_HOST"
python connectors/run.py all --limit 10
```

By default QRadar sends are dry-run payloads. Add `--qradar-live` only after
the syslog target is confirmed.

## Common environment variables
- `CONNECTOR_VERIFY_TLS`: global TLS verification default, `true` by default.
- `<PRODUCT>_BASE_URL` or product alias such as `VAULT_ADDR`.
- `<PRODUCT>_API_TOKEN` or product alias such as `VAULT_TOKEN`.
- `<PRODUCT>_API_PATH`: endpoint path to call.
- `<PRODUCT>_JSON_ROOT`: optional dotted path for extracting a list from the
  JSON response, for example `data.items`.
- `<PRODUCT>_TIMEOUT`: request timeout in seconds.

Default API paths are intentionally conservative and can be overridden per lab
endpoint without code changes.
