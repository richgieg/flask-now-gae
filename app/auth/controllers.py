from datetime import datetime

from flask import current_app, session
from google.appengine.api import memcache
from google.appengine.ext import ndb
from itsdangerous import Signer, SignatureExpired, BadSignature, \
    TimedJSONWebSignatureSerializer as Serializer

from .. import login_manager, send_email
from ..main.models import Profile
from .models import Invite, Role, User
from .settings import UserRoles


class AuthController:

    ###########################################################################
    ###     User methods
    ###########################################################################

    @staticmethod
    @login_manager.user_loader
    def load_user(user_id):
        return AuthController.get_user(int(user_id))

    @staticmethod
    @login_manager.token_loader
    def load_user_from_signed_token(signed_token):
        s = Signer(current_app.config['SECRET_KEY'])
        auth_token = None
        try:
            auth_token = s.unsign(signed_token)
        except:
            pass
        if auth_token:
            user = User.query().filter(User.auth_token == auth_token).get()
            if user:
                session['auth_token'] = user.auth_token
                return user
        # This causes Flask-Login to clear the "remember me" cookie. This could
        # break if Flask-Login's internal implementation changes. A better way
        # should be implemented. Perhaps install an after_request hook.
        session['remember'] = 'clear'
        return None

    @staticmethod
    def ping_user(user):
        user.last_seen = datetime.utcnow()
        user.put()

    @staticmethod
    def generate_confirmation_token(user, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm': user.id})

    @staticmethod
    def confirm_user(user, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return False
        except BadSignature:
            return False
        if data.get('confirm') != user.id:
            return False
        user.confirmed = True
        user.put()
        return True

    @staticmethod
    def generate_email_change_token(user, new_email, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'change_email': user.id, 'new_email': new_email})

    @staticmethod
    def change_email(user, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return False
        except BadSignature:
            return False
        if data.get('change_email') != user.id:
            return False
        new_email = data.get('new_email')
        if new_email is None:
            return False
        if User.query().filter(User.email == new_email).get() is not None:
            return False
        user.email = new_email
        user.update_avatar_hash()
        user.update_auth_token()
        user.put()
        return True

    @staticmethod
    def generate_reset_token(user, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'reset': user.id})

    @staticmethod
    def reset_password(user, token, new_password):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return False
        except BadSignature:
            return False
        if data.get('reset') != user.id:
            return False
        user.password = new_password
        user.put()
        return True

    @staticmethod
    def change_username(user, username):
        user.username = username
        user.update_auth_token()
        user.put()

    @staticmethod
    def can_register():
        if not current_app.config['APP_ALLOW_NEW_USERS']:
            return False
        else:
            if not current_app.config['APP_MAX_USERS']:
                return True
            else:
                return (
                    User.query().count() < current_app.config['APP_MAX_USERS']
                )

    @staticmethod
    def register(email, username, password):
        user = User(email=email, username=username)
        user.password = password
        try:
            AuthController._register(user)
        except:
            return None
        try:
            memcache.add(key='registration', value=True, time=60)
        except:
            pass
        return user

    @staticmethod
    @ndb.transactional
    def _register(user):
        """Ensures that the user and profile entities are both created
        successfully, or neither is created."""
        user.put()
        profile = Profile(parent=user.key)
        profile.put()
        user.profile_key = profile.key
        user.put()

    @staticmethod
    def is_registration_in_memcache():
        try:
            if memcache.get(key='registration'):
                return True
            else:
                return False
        except:
            return False

    @staticmethod
    def get_expired_users():
        return User.query(
            User.pvt__active == False,
            User.expires <= datetime.utcnow()
        ).fetch()

    @staticmethod
    def get_users(order=None):
        query = User.query()
        if order:
            query = query.order(order)
        return query.fetch()

    @staticmethod
    def get_admins(order=None):
        admin_role_key = Role.query(Role.name == 'Administrator').get().key
        query = User.query(User.role_key == admin_role_key)
        if order:
            query = query.order(order)
        return query.fetch()

    @staticmethod
    def get_keys(user_list):
        """Returns two tuples of keys, for users and their associated profiles.

        Iterates over the given list of users and compiles two tuples of keys.
        The first tuple contains the user keys and the second contains the
        profile keys.

        Args:
            user_list: List of user entities

        Returns:
            A list containing two tuples is returned, of user keys and profile
            keys. If user_list is empty, then a list containing two empty
            tuples is returned.
        """
        if not user_list:
            return [(), ()]
        return zip(*[(u.key, u.profile_key) for u in user_list])

    @staticmethod
    def get_user(id):
        """Returns the User entity affiliated with the given ID."""
        return ndb.Key(User, id).get()

    ###########################################################################
    ###     Role methods
    ###########################################################################

    @staticmethod
    def get_role(id):
        """Returns the Role entity affiliated with the given ID."""
        return ndb.Key(Role, id).get()

    @staticmethod
    def get_roles():
        """Returns all Role entities."""
        return Role.query().order(Role.name).fetch()

    @staticmethod
    def get_roles_dict():
        """Returns a dictionary that maps role keys to role names."""
        return {r.key: r.name for r in AuthController.get_roles()}

    @staticmethod
    def insert_roles():
        for r in UserRoles.ROLES:
            role = Role.query().filter(Role.name == r).get()
            if role is None:
                role = Role(name=r)
            role.permissions = UserRoles.ROLES[r][0]
            role.default = UserRoles.ROLES[r][1]
            role.put()

    ###########################################################################
    ###     Invite methods
    ###########################################################################

    @staticmethod
    def notify_inviter(email):
        invite = (
            Invite.query(ancestor=Invite.get_parent_key())
                  .filter(Invite.email == email)
                  .get()
        )
        if invite:
            inviter = User.query().filter(User.email == invite.inviter).get()
            send_email(inviter.email, 'Your Invitee Has Registered!',
                       'auth/email/invite_accepted', inviter=inviter,
                       invitee=email)

    @staticmethod
    def create_invite(email, inviter):
        # If old invite exists for the email address, remove it first.
        AuthController.remove_invite(email)
        expires = datetime.utcnow() + current_app.config['APP_INVITE_TTL']
        Invite(email=email, inviter=inviter, expires=expires,
               parent=Invite.get_parent_key()).put()

    @staticmethod
    def remove_invite(email):
        invite = (
            Invite.query(ancestor=Invite.get_parent_key())
                  .filter(Invite.email == email)
                  .get()
        )
        if invite:
            invite.key.delete()

    @staticmethod
    def is_invite_pending(email):
        AuthController.remove_stale_invites()
        invite = (
            Invite.query(ancestor=Invite.get_parent_key())
                  .filter(Invite.email == email)
                  .get()
        )
        return invite is not None

    @staticmethod
    def pending_invites():
        AuthController.remove_stale_invites()
        if Invite.query(ancestor=Invite.get_parent_key()).get():
            return True
        return False

    @staticmethod
    def remove_stale_invites():
        stale_invites = (
            Invite.query(ancestor=Invite.get_parent_key())
                  .filter(Invite.expires <= datetime.utcnow())
                  .fetch()
        )
        ndb.delete_multi([invite.key for invite in stale_invites])
