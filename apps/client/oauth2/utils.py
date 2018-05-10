class OAuth2Error(Exception):
    error = {'error': None}

    def __init__(self, message, error, state=None):
        self.message = message if message else error
        self.error = error
        self.state = state
        super(Exception, self).__init__(self.message)

    def __str__(self):
        return u'error: %s, description: %s' % (self.error, self.message)
