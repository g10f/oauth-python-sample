docker run \
  -p 8000:8000 \
  -e SECRET_KEY \
  -e DATABASE_URL=postgres://client:client@host.docker.internal:5432/client \
  -e FORWARDED_ALLOW_IPS='*' \
  ghcr.io/g10f/oauth-python-sample
