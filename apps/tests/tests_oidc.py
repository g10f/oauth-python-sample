from django.urls import reverse

from tests.tests import SSOSeleniumTests


class OIDCSeleniumTests(SSOSeleniumTests):
    fixtures = ['idp.json', 'client.json']

    def test_native_login(self):
        self.selenium.get('%s%s' % (self.live_server_url, reverse('login')))
        self.selenium.find_element_by_id("29").click()
        self.login('dv20srf', 'ibsgok#0418')
        self.wait_page_loaded()


        pass
