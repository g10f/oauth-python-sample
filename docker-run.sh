docker run \
  -p 8000:8000 \
  -e DATABASE_HOST=host.docker.internal \
  -e FORWARDED_ALLOW_IPS=* \
  g10f/oauth-python-sample

