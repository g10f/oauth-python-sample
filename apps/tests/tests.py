import os

from selenium.webdriver.chrome.webdriver import WebDriver
# from selenium.webdriver.firefox.webdriver import WebDriver
from django.contrib.staticfiles.testing import StaticLiveServerTestCase
from django.urls import reverse


class SSOSeleniumTests(StaticLiveServerTestCase):
    # fixtures = ['user_data.json']

    @classmethod
    def setUpClass(cls):
        cls.port = 8001
        super().setUpClass()
        cls.selenium = WebDriver()
        cls.selenium.implicitly_wait(10)

    @classmethod
    def tearDownClass(cls):
        cls.selenium.quit()
        super().tearDownClass()

    def login(self, username, password):
        driver = self.selenium
        driver.find_element_by_id("username").send_keys(username)
        driver.find_element_by_id("password").send_keys(password)

        driver.find_element_by_tag_name("form").submit()

        # Wait until the response is received
        self.wait_page_loaded()

    def logout(self):
        self.selenium.get('%s%s' % (self.live_server_url, reverse('accounts:logout')))
        # Wait until the response is received
        self.wait_page_loaded()

    def wait_until(self, callback, timeout=10):
        """
        Helper function that blocks the execution of the tests until the
        specified callback returns a value that is not falsy. This function can
        be called, for example, after clicking a link or submitting a form.
        See the other public methods that call this function for more details.
        """
        from selenium.webdriver.support.wait import WebDriverWait
        WebDriverWait(self.selenium, timeout).until(callback)

    def wait_loaded_tag(self, tag_name, timeout=10):
        """
        Helper function that blocks until the element with the given tag name
        is found on the page.
        """
        self.wait_until(
            lambda driver: driver.find_element_by_tag_name(tag_name),
            timeout
        )

    def wait_page_loaded(self):
        """
        Block until page has started to load.
        """
        from selenium.common.exceptions import TimeoutException
        try:
            # Wait for the next page to be loaded
            self.wait_loaded_tag('body')
        except TimeoutException:
            # IE7 occasionnally returns an error "Internet Explorer cannot
            # display the webpage" and doesn't load the next page. We just
            # ignore it.
            pass
