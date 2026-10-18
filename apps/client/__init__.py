import os

# The version is the git tag of the release, the CI passes it to the image as environment variable.
__version__ = os.environ.get('VERSION', 'dev')
