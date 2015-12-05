import os
from datetime import timedelta

from google.appengine.api import app_identity


class Config:
    ###########################################################################
    # [ Application ]
    ###########################################################################
    APP_TITLE = 'WebApp'
    APP_MAIL_NAME = '{} Support'.format(APP_TITLE)
    APP_MAIL_ADDRESS = 'support@{}.appspotmail.com'.format(
        app_identity.get_application_id())
    APP_MAIL_SENDER = '{} <{}>'.format(APP_MAIL_NAME, APP_MAIL_ADDRESS)
    APP_MAIL_SUBJECT_PREFIX = '[{}]'.format(APP_TITLE)
    # Allow new users to register.
    APP_ALLOW_NEW_USERS = True
    # A value of 0 means unlimited.
    APP_MAX_USERS = 10
    # If false, users must be invited by an administrator.
    APP_OPEN_REGISTRATION = False
    # Time-to-live for a user registration invitation. This only has
    # an effect if APP_OPEN_REGISTRATION is false.
    APP_INVITE_TTL = timedelta(minutes=15)

    ###########################################################################
    # [ Flask ]
    ###########################################################################
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard to guess string'

    ###########################################################################
    # [ Flask-Login ]
    ###########################################################################
    # Ensures that the "remember me" cookie isn't accessible by
    # client-sides scripts.
    REMEMBER_COOKIE_HTTPONLY = True
    # Time-to-live for the "remember me" cookie.
    REMEMBER_COOKIE_DURATION = timedelta(days=365)
    # Must be disabled for the application's security layer to
    # function properly.
    SESSION_PROTECTION = None

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    ###########################################################################
    # [ Flask ]
    ###########################################################################
    DEBUG = True


class ProductionConfig(Config):
    ###########################################################################
    # [ Flask ]
    ###########################################################################
    # Comment the following line if you're not running HTTPS.
    SESSION_COOKIE_SECURE = True

    ###########################################################################
    # [ Flask-Login ]
    ###########################################################################
    # Comment the following line if you're not running HTTPS.
    REMEMBER_COOKIE_SECURE = True


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,

    'default': DevelopmentConfig
}
