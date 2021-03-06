from datetime import datetime

import webapp2
from google.appengine.api import mail
from google.appengine.ext import ndb

from app.auth.controllers import AuthController
from app.auth.models import Role, User
from config import Config


def send_email(to, subject, body):
    sender = Config.APP_MAIL_SENDER
    subject = Config.APP_MAIL_SUBJECT_PREFIX + ' ' + subject
    mail.send_mail(sender, to, subject, body)


def send_email_to_admins(subject, body=''):
    for admin in AuthController.get_admins():
        send_email(admin.email, subject, body)


class RemoveDeactivatedUserAccounts(webapp2.RequestHandler):
    def get(self):
        """Removes all deactivated user accounts that have expired."""
        try:
            users = AuthController.get_expired_users()
            if not users:
                return
            user_keys, profile_keys = AuthController.get_keys(users)
            ndb.delete_multi(user_keys)
            ndb.delete_multi(profile_keys)
            body = '\n'.join([user.username for user in users])
            send_email_to_admins(
                'RemoveDeactivatedUserAccounts succeeded!', body=body)
        except Exception as e:
            send_email_to_admins(
                'RemoveDeactivatedUserAccounts failed!', body=e)


app = webapp2.WSGIApplication([
    ('/cron/remove_deactivated_user_accounts', RemoveDeactivatedUserAccounts),
], debug=True)
