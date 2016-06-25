from django import template
from django.core.urlresolvers import reverse

register = template.Library()


@register.simple_tag(takes_context=True)
def active(context, viewname):
    path = context['request'].path
    if path == reverse(viewname):
        return 'active'
    return ''
