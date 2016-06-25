# -*- coding: utf-8 -*-
import os
from fabric import api
from fabric.contrib import files
from fabtools import require
import fabtools

api.env.use_ssh_config = True
api.env.apps = ['client']

PROJECT_NAME = 'oauth-python-sample'
LOCAL_PYTHON = '~/envs/test/bin/python'


@api.task
def compilemessages():
    for app in api.env.apps:
        with api.lcd('apps/%s' % app):
            api.local('django-admin.py compilemessages')


@api.task
def makemessages():
    for app in api.env.apps:
        with api.lcd('apps/%s' % app):
            api.local('django-admin.py makemessages -a ')


def test():
    with api.lcd('apps'):
        api.local("%s ./manage.py test oauth2" % LOCAL_PYTHON)


def commit():
    api.local("git commit -a")
    api.local("git push -u origin master")
    # api.local("hg commit")


def push(app):
    # api.local("hg push ssh://hg@bitbucket.org/dwbn/%(app)s" % {'app': app})
    api.local("git push -u origin master")


@api.task
def prepare_deploy(app=PROJECT_NAME):
    #   test()
    commit()
    push(app)


@api.task
def compileless(version='1.0.5'):
    for style in ['style']:
        api.local('lessc ./apps/client/static/less/%(style)s.less ./apps/client/static/css/%(style)s-%(version)s.css' % {'style': style, 'version': version})


def working_copy(code_dir):
    require.directory(code_dir)
    with api.cd(code_dir):
        require.git.working_copy('git@bitbucket.org:dwbn/oauth-python-sample.git', path='src')
        api.sudo("chown www-data:www-data -R  ./src")
        api.sudo("chmod g+w -R  ./src")

    require.directory(os.path.join(code_dir, 'config'))


PROXIED_SITE_TEMPLATE = """\
upstream %(server_name)s.backend {
    server unix:/tmp/%(server_name)s.gunicorn.sock;
}
server {
    listen [::]:80;
    listen      80;
    server_name %(server_name)s;
    # path for static files
    root %(docroot)s;
    return 301 https://%(server_name)s$request_uri;
}
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    # listen 443 ssl default_server;
    server_name %(server_name)s;
    add_header Strict-Transport-Security max-age=31536000;
    ssl_certificate /etc/letsencrypt/live/%(cert)s/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/%(cert)s/privkey.pem;
    ssl_dhparam /etc/nginx/dhparam.pem;

    # path for static files
    root %(docroot)s;

    try_files $uri @proxied;

    location @proxied {
        # limit_req zone=sso burst=10 nodelay;
        add_header X-UA-Compatible IE=edge;
        add_header Strict-Transport-Security max-age=31536000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_redirect off;
        proxy_pass http://%(server_name)s.backend;
    }
    location ~ ^/robots.txt$ {alias /proj/static/htdocs/%(server_name)s/static/txt/robots.txt; }

    error_log                %(project_dir)s/logs/nginx-error.log error;
    access_log               %(project_dir)s/logs/nginx-access.log;
}
"""


_PROXIED_SITE_TEMPLATE = """\
upstream %(server_name)s.backend {
    #server unix:/tmp/%(server_name)s.gunicorn.sock;
    server 127.0.0.1:%(backend_port)s;
}
server {
    listen 80;
    server_name %(server_name)s;
    # path for static files
    root %(docroot)s;
    return 301 https://$server_name$request_uri;
}
server {
    listen 443 ssl;
    server_name %(server_name)s;

    # path for static files
    root %(docroot)s;

    try_files $uri @proxied;

    location @proxied {
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_redirect off;
        proxy_pass http://%(server_name)s.backend;
    }
    error_log %(project_dir)s/logs/nginx-error.log error;
    access_log %(project_dir)s/logs/nginx-access.log;
}
"""

GUNICORN_TEMPLATE = """\
import multiprocessing
import os

bind = "unix:/tmp/%(server_name)s.gunicorn.sock"
#bind = "127.0.0.1:%(backend_port)s"
workers = 1  # multiprocessing.cpu_count() + 1
pythonpath = '%(code_dir)s/apps'
errorlog = '%(project_dir)s/logs/gunicorn-error.log'
os.environ['DEBUG'] = ""
"""


def update_dir_settings(directory):
    with api.cd(directory):
        api.sudo("chown www-data:www-data -R  ./logs")
        api.sudo("chmod 0660 -R  ./logs")
        api.sudo("chmod +X -R %s" % directory)
        api.sudo("chmod g+X -R %s" % directory)


@api.task
def deploy(app=PROJECT_NAME):
    server_name = 'oauth-python-sample.g10f.de'
    project_dir = '/proj/%s' % server_name
    code_dir = project_dir + '/src'
    apps_dir = code_dir + '/apps'
    virtualenv = 'test'
    backend_port = 8888
    working_copy(project_dir)

    """
    # Require a Python package
    fabtools.require.python.virtualenv('/envs/test')
    with fabtools.python.virtualenv('/envs/test'):
        require.python.package('django')
        require.python.package('psycopg2')
        require.python.package('httplib2')
        require.python.package('docutils')
        require.python.package('gunicorn')
        require.python.package('pyopenssl')
        require.python.package('pillow')
        require.python.package('sorl-thumbnail')

    # startcom root cert seems to be now available by default
    # require.file('/envs/test/lib/python2.7/site-packages/httplib2/cacerts.txt', source='/usr/local/lib/python2.7/dist-packages/httplib2/cacerts.txt')

    # Require a PostgreSQL server
    require.postgres.server()
    require.postgres.user('client', 'client')
    require.postgres.database('client', 'client')

    # gunicorn
    require.directory('%(project_dir)s/config' % {'project_dir': project_dir}, use_sudo=True, owner="www-data", mode='770')
    config_filename = '%(project_dir)s/config/gunicorn_%(server_name)s.py' % {'project_dir': project_dir, 'server_name': server_name}
    context = {
        'backend_port': backend_port,
        'server_name': server_name,
        'code_dir': code_dir,
        'project_dir': project_dir
    }
    require.files.template_file(config_filename, template_contents=GUNICORN_TEMPLATE, context=context, use_sudo=True)

    # supervisor process for our app
    require.supervisor.process(
            server_name,
            command='/envs/%(virtualenv)s/bin/gunicorn -c %(config_filename)s %(app)s.wsgi:application' % {'virtualenv': virtualenv, 'config_filename': config_filename, 'app': 'client'},
            directory=code_dir + '/apps',
            user='www-data',
            startsecs=2
    )

    # nginx server proxying to our app
    require.directory('%(project_dir)s/logs' % {'project_dir': project_dir}, use_sudo=True, owner="www-data", mode='770')
    require.nginx.site(
        server_name,
        template_contents=PROXIED_SITE_TEMPLATE,
        docroot='/proj/static/htdocs/%(server_name)s' % {'server_name': server_name},
        project_dir=project_dir,
        backend_port=backend_port,
        cert=server_name,
    )

    update_dir_settings(project_dir)
    """
    with api.cd(code_dir):
        python = '/envs/%(virtualenv)s/bin/python' % {'virtualenv': virtualenv}
        api.sudo("%s ./apps/manage.py migrate" % python, user='www-data', group='www-data')

        # api.run("%s ./apps/manage.py syncdb" % python)
        api.run("%s ./apps/manage.py collectstatic --noinput" % python)

    api.run("sudo supervisorctl restart %(server_name)s" % {'server_name': server_name})

    # update_dir_settings(code_dir + '/logs')
