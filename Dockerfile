FROM python:3.12 as builder

ENV WORKDIR=/opt/g10f/sample
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV VIRTUAL_ENV=$WORKDIR/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

RUN apt-get update -y && apt-get -y install python3-venv

WORKDIR $WORKDIR
RUN chown -R $USERNAME: $WORKDIR

COPY requirements.txt .
COPY requirements requirements
RUN python3 -m venv $VIRTUAL_ENV
RUN pip install -U pip wheel
RUN pip install -r requirements.txt

#####################################################
FROM python:3.12-slim

RUN apt-get update -y && apt-get -y install postgresql-client postgresql-client-common && apt-get clean

ENV WORKDIR=/opt/g10f/sample
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV VIRTUAL_ENV=$WORKDIR/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

ARG USERNAME=worker
ARG USER_UID=1000
ARG USER_GID=$USER_UID
# required to run collectstatic
ARG SECRET_KEY=dummy

# Create the user
RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME

COPY --from=builder $VIRTUAL_ENV $VIRTUAL_ENV

WORKDIR $WORKDIR/apps
COPY apps .
COPY Docker/gunicorn.conf.py ./gunicorn.conf.py

RUN chown -R $USERNAME: /opt/g10f

USER $USERNAME
ARG SECRET_KEY=dummy
RUN ./manage.py collectstatic
ENTRYPOINT ["./docker-entrypoint.sh"]
# Start gunicorn
CMD ["gunicorn", "client.wsgi:application", "--bind 0.0.0.0:8000", "-w", "2"]
EXPOSE 8000
