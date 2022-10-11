import json
import logging
from functools import wraps

from django.contrib.flatpages import models
from django.http import HttpResponse
from django.shortcuts import render
from django.urls import reverse
from django.utils.translation import gettext as _

logger = logging.getLogger(__name__)


class HttpResponseNotAuthorized(HttpResponse):

    def __init__(self, callback=None):
        status = 401
        content = json.dumps(
            {'error': 'not_authorized', 'error_description': _('The request requires user authentication'),
             'code': 401})
        if callback:
            status = 200
            content = u"%s(%s)" % (callback, content)

        HttpResponse.__init__(self, content, status=status, content_type='application/json')

        self['Access-Control-Allow-Origin'] = '*'
        self['Access-Control-Allow-Headers'] = 'Authorization'


def api_user_passes_test(test_func):
    """
    Decorator for views that checks that the user passes the given test,
    returning HTTP 401  if necessary. The test should be a callable
    that takes the user object and returns True if the user passes.
    """

    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if test_func(request.user):
                return view_func(request, *args, **kwargs)
            if 'callback' in request.GET:
                return HttpResponseNotAuthorized(callback=request.GET['callback'])
            else:
                return HttpResponseNotAuthorized()

        return _wrapped_view

    return decorator


@api_user_passes_test(lambda u: u.is_authenticated)
def api_test(request, template="api.html"):
    try:
        flatpage = models.FlatPage.objects.get(url=reverse('api_test'))
    except models.FlatPage.DoesNotExist:
        flatpage = None
        logger.warning('FlatPage %s does not exist' % reverse('api_test'))

    context = {
        'flatpage': flatpage,
        'user': request.user,
        'scopes': request.scopes,
        'client': request.client
    }
    return render(request, template, context=context)


def home(request, template="home.html"):
    try:
        flatpage = models.FlatPage.objects.get(url=reverse('home'))
    except models.FlatPage.DoesNotExist:
        flatpage = None
        logger.warning('FlatPage %s does not exist' % reverse('home'))

    context = {
        'flatpage': flatpage,
    }
    return render(request, template, context=context)
