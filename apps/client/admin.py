from functools import update_wrapper

from django.contrib import admin
from django.contrib.flatpages.admin import FlatPageAdmin
from django.contrib.flatpages.models import FlatPage
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect


class AdminSite(admin.sites.AdminSite):
    """
    copy of django admin view, which is 
    - redirecting to login instead of admin:login 
    - displaying an error message if the user is authenticated but has not admin access
    """

    def admin_view(self, view, cacheable=False):
        def inner(request, *args, **kwargs):
            if not self.has_permission(request):
                if request.user.is_authenticated():
                    return render(request, 'oauth2/error.html',
                                  context={'error': "User %s does not have admin access." % request.user.username})
                else:
                    if request.path == reverse('admin:logout', current_app=self.name):
                        index_path = reverse('admin:index', current_app=self.name)
                        return HttpResponseRedirect(index_path)
                    # Inner import to prevent django.contrib.admin (app) from
                    # importing django.contrib.auth.models.User (unrelated model).
                    from django.contrib.auth.views import redirect_to_login
                    return redirect_to_login(request.get_full_path(), reverse('login'))
            return view(request, *args, **kwargs)

        if not cacheable:
            inner = never_cache(inner)
        # We add csrf_protect here so this function can be used as a utility
        # function for any view, without having to repeat 'csrf_protect'.
        if not getattr(view, 'csrf_exempt', False):
            inner = csrf_protect(inner)
        return update_wrapper(inner, view)


site = AdminSite()

site.register(FlatPage, FlatPageAdmin)
