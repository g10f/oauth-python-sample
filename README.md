OAuth2 / OpenID Connect sample client
=====================================
Django web app that logs in at an OpenID Connect identity provider with the authorization code flow
and shows the ID token, the access token and the user info of the logged in user.

Identity providers and clients are configured in the Django admin (`/admin/`). The fixture
`initial_data` contains an example configuration.

Pages
-----

| URL                        | Description                                         |
|----------------------------|-----------------------------------------------------|
| `/`                        | start page                                          |
| `/oauth2/login/`           | starts the login at the identity provider           |
| `/oauth2/logout/`          | logout, also at the identity provider               |
| `/oauth2/userinfo/me/`     | user info of the logged in user                     |
| `/oauth2/tokeninfo/me/`    | token info of the access token                      |
| `/oauth2/userinfo/client/` | user info loaded in the browser with JavaScript (implicit client profile) |
| `/oauth2/session/`         | session data                                        |
| `/api/v1/test/`            | page for testing an API with the access token       |
| `/admin/`                  | Django admin                                        |

Configuration
-------------
Environment variables:

| Variable                                  | Default                                          | Description                                  |
|-------------------------------------------|--------------------------------------------------|----------------------------------------------|
| `DATABASE_URL`                            | `postgres://client:client@localhost:5432/client` | PostgreSQL database                          |
| `SECRET_KEY`                              | fixed development key                            | Django secret key, set it in production      |
| `ALLOWED_HOSTS`                           | `oauth-python-sample.g10f.de`                    | comma separated list, localhost is always allowed |
| `OPENID_SSO_SERVER_BASE_URL`              | `https://sso.g10f.de/`                           | base URL of the identity provider            |
| `ALWAYS_REFRESH_TOKENS`                   | `False`                                          | refresh the tokens on every request          |
| `SSO.STAFF_GROUPS`                        | `Staff,Superuser`                                | groups that get staff status                 |
| `SSO.SUPERUSER_GROUP`                     | `Superuser`                                      | group that gets superuser status             |
| `ABOUT_URL`                               | `https://g10f.de/`                               | target of the about link                     |
| `ENABLE_PLAUSIBLE`, `DOMAIN`              | `False`, `localhost:8000`                        | Plausible analytics                          |
| `EMAIL_HOST`, `EMAIL_PORT`                | `localhost`, `25`                                | mail server for error mails                  |
| `DEFAULT_FROM_EMAIL`, `SERVER_EMAIL`      | `webmaster@g10f.de`                              | sender of mails                              |
| `ROOT_LOG_LEVEL`, `DJANGO_LOG_LEVEL`, `REQUESTS_LOG_LEVEL` | `INFO`                          | log levels                                   |

The entrypoint of the image evaluates:

| Variable                   | Description                                                        |
|----------------------------|--------------------------------------------------------------------|
| `DJANGO_MIGRATE=on`        | runs `manage.py migrate` on start                                  |
| `DJANGO_CREATE_SUPERUSER=on` | creates a superuser (`DJANGO_SUPERUSER_USERNAME`, `DJANGO_SUPERUSER_PASSWORD`) if there are no users |
| `DJANGO_LOAD_INITIAL_DATA=on` | loads the fixture `initial_data` if there are no users          |

`DEBUG` is on only with `manage.py runserver`.

Development
-----------
A PostgreSQL database with user, password and database `client` on localhost is required.

    python3 -m venv .venv
    .venv/bin/pip install -r requirements.txt
    cd apps
    ../.venv/bin/python manage.py migrate
    ../.venv/bin/python manage.py loaddata initial_data
    ../.venv/bin/python manage.py runserver

Or with docker compose (uses the database on the host):

    docker compose up --build

The CSS is built from `apps/static/scss` with Sass. The build also copies Bootstrap, jQuery and the
Bootstrap icons from `node_modules` to `apps/static`. The results are committed.

    npm install
    npm run build

Release
-------
A release is a git tag `X.Y.Z`. It is created with `git release` (a small release script):

    git release patch        # or minor, major, X.Y.Z

It writes the new version to `apps/client/__init__.py`, commits it as `release X.Y.Z`,
creates the tag and pushes both. The CI checks that the tag matches `__version__`.

The CI builds the image `ghcr.io/g10f/oauth-python-sample:X.Y.Z` (and `latest`) natively for amd64
and arm64 and deploys it. A push without a tag does not start the CI.
