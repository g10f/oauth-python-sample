FROM python:3.13.5-slim

# Install packages needed to run your application (not build deps):
ENV RUN_DEPS="postgresql-client"
ENV BUILD_DEPS="build-essential libpq-dev"
RUN set -ex \
    && apt-get update && apt-get install -y --no-install-recommends $RUN_DEPS \
    && rm -rf /var/lib/apt/lists/*

ENV WORKDIR=/opt/g10f/sample
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV VIRTUAL_ENV=$WORKDIR/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

WORKDIR $WORKDIR
RUN chown -R $USERNAME: $WORKDIR

COPY requirements.txt .
COPY requirements requirements

RUN set -ex \
    && apt-get update && apt-get install -y --no-install-recommends $BUILD_DEPS \
    && python3 -m venv ${VIRTUAL_ENV} \
    && pip install -U pip wheel \
    && pip install --no-cache-dir -r requirements.txt \
    && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false $BUILD_DEPS \
    && rm -rf /var/lib/apt/lists/*

ARG USERNAME=worker
ARG USER_UID=1000
ARG USER_GID=$USER_UID
# required to run collectstatic
ARG SECRET_KEY=dummy

# Create the user
RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME

COPY apps .

RUN chown -R $USERNAME: /opt/g10f

USER $USERNAME
ARG SECRET_KEY=dummy
RUN ./manage.py collectstatic
ENTRYPOINT ["./docker-entrypoint.sh"]
# Start gunicorn
CMD ["gunicorn", "client.wsgi:application", "-b", "0.0.0.0:8000", "--forwarded-allow-ips", "*"]
EXPOSE 8000
