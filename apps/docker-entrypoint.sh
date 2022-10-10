#!/usr/bin/env bash
set -exf


if [ "x$DJANGO_MIGRATE" = 'xon' ]; then
	./manage.py migrate --noinput
fi

if  [[ x$DJANGO_CREATE_SUPERUSER = xon ]]; then
  user_count=$(./manage.py user_count)

  if [[ $user_count = 0  ]]; then

    if  [[ x$DJANGO_CREATE_SUPERUSER = xon ]]; then
      ./manage.py createsuperuser --noinput
    fi

  fi
fi

# shellcheck disable=SC2068
exec $@
