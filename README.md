# acme-git-webhook

FastAPI webhook that provisions ACME DNS-01 challenges by adding/removing
TXT records in Bind zone files stored in a Git repository.

## How it works

```
ACME client (certbot/acme.sh)
        │
        │  POST /acme/auth { domain, validation }
        │  POST /acme/cleanup { domain }
        ▼
acme-git-webhook
        │
        │  1. git pull
        │  2. dnspython: update zone file
        │  3. git commit + push
        ▼
GitHub repository (Bind zone files)
        │
        │  CI/CD detects push
        ▼
Authoritative DNS servers (rndc reload)
```

The ACME client calls the webhook twice per certificate:
1. **auth** — injects `_acme-challenge.<domain>. IN TXT "<validation>"` into the zone file and pushes to Git
2. **cleanup** — removes the TXT record after validation

## Configuration

Edit `config.yaml`:

```yaml
auth:
  api_keys:
    - "sk-XXXXXXXXXXXX"

repo:
  url: "git@github.com:org/dns-zones.git"
  branch: "main"
  zone_path: "zones"
  zone_file_suffix: ".zone"
```

Zone files are named `<zone_name>.zone` (e.g. `example.com.zone`) and
located under `zone_path`. The webhook resolves the correct zone by
trying progressively shorter domain suffixes.

## API

| Endpoint | Method | Auth | Body | Description |
|---|---|---|---|---|
| `/health` | GET | No | — | Healthcheck |
| `/acme/auth` | POST | Bearer | `{ "domain", "validation" }` | Add TXT record |
| `/acme/cleanup` | POST | Bearer | `{ "domain" }` | Remove TXT record |

## Deployment

```bash
docker compose up --build
```

Mount your SSH deploy key at `/run/secrets/deploy_key` and set the
`CONFIG_PATH` environment variable if needed.

## Development

```bash
make test        # install venv + run pytest
make lint        # syntax check
make check       # lint + test
make clean       # remove venv and caches
```

## Tests

```bash
pip install -r dev-requirements.txt
pytest -v
```

## License

MIT
