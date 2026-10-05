"""Test-only settings: run the Django test suite against SQLite.

The deployment database user is granted rights on the application database only,
so `manage.py test` cannot create a test_honeypot_db database. Using SQLite keeps
the unit suite runnable inside the deployed container while still exercising all
application, model and view logic.
"""
import os

from .settings import *  # noqa: F401,F403

# settings.SECRET_KEY comes from the environment; provide a test-only value when it
# is absent (e.g. running the suite on a developer machine) so session signing works.
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY") or "test-only-key-not-for-production"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "test_runner.sqlite3",  # noqa: F405
    }
}