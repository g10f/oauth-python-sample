"""
This file demonstrates writing tests using the unittest module. These will pass
when you run "manage.py test".

Replace this with more appropriate tests for your application.
"""

from django.core.urlresolvers import reverse
from django.test import TestCase


class OAuth2Tests(TestCase):

    def test_login_view_with_error_code(self):
        response = self.client.get(reverse('login') + "?error=testerror")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "testerror")
