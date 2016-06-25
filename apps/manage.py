#!/usr/bin/env python
import os
import sys

if __name__ == "__main__":
    DIRNAME = os.path.dirname(__file__)
    sys.path.insert(0, DIRNAME)

    os.environ["DJANGO_SETTINGS_MODULE"] = "client.settings"

    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)
