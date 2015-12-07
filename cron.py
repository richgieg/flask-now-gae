from datetime import datetime

import webapp2
from google.appengine.ext import ndb
from app.auth.models import Role, User


def send_email_to_admins():
    for admin in User.get_admins():
        print(admin.username)


class RemoveDeactivatedUserAccounts(webapp2.RequestHandler):
    def get(self):
        """Removes all deactivated user accounts that have expired."""
        users = User.get_expired_users()
        # if users:
        #     user_keys, profile_keys = (
        #         zip(*[(u.key, u.username) for u in User.get_expired_users()])
        #     )

        # # ndb.delete_multi(user_keys)


app = webapp2.WSGIApplication([
    ('/cron/remove_deactivated_user_accounts', RemoveDeactivatedUserAccounts),
], debug=True)
