# AHRAS Production Deployment

## 1. Prepare secrets

Copy `.env.production.example` to `.env` and replace every placeholder with real values.
Generate a strong secret with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

Do not commit `.env` or TLS private keys.

## 2. TLS certificates

Place the certificate and private key at:

```text
nginx/ssl/fullchain.pem
nginx/ssl/privkey.pem
```

Set `PUBLIC_HOSTNAME` in `.env`. The Nginx configuration redirects HTTP to HTTPS.

## 3. Start

```bash
docker compose --env-file .env -f docker-compose.prod.yml up -d --build
```

Check:

```bash
docker compose -f docker-compose.prod.yml ps
curl -f https://YOUR_HOST/health
```

## 4. Backup

```bash
docker compose --env-file .env -f docker-compose.prod.yml --profile backup run --rm backup
```

Backups are stored in `./backups`. Keep this directory outside the application host in a real deployment as well (object storage or another machine).

## 5. Restore

Stop AHRAS before a destructive restore:

```bash
docker compose -f docker-compose.prod.yml stop ahras
MONGO_ROOT_USERNAME=... MONGO_ROOT_PASSWORD=... MONGO_DB=AHRAS_DB \
  ./deploy/restore.sh ./backups/YYYYMMDDTHHMMSSZ
```

Start AHRAS again and verify `/health`.

## 6. Logs

```bash
docker compose -f docker-compose.prod.yml logs -f ahras
```

Never expose MongoDB directly to the public internet. The production compose file keeps MongoDB on an internal Docker network.
