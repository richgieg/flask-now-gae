from datetime import datetime, timedelta
import hashlib
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import Signer, TimedJSONWebSignatureSerializer as Serializer,\
    SignatureExpired, BadSignature
from flask import current_app, request, session
from flask.ext.login import UserMixin, AnonymousUserMixin, make_secure_token
from . import db, login_manager


class AccountPolicy:
    LOCKOUT_POLICY_ENABLED = True
    LOCKOUT_THRESHOLD = 5
    RESET_THRESHOLD_AFTER = timedelta(minutes=30)


class Permission:
    FOLLOW = 0x01
    COMMENT = 0x02
    WRITE_ARTICLES = 0x04
    MODERATE_COMMENTS = 0x08
    ADMINISTER = 0x80


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')

    @staticmethod
    def insert_roles():
        roles = {
            'User': (Permission.FOLLOW |
                     Permission.COMMENT |
                     Permission.WRITE_ARTICLES, True),
            'Moderator': (Permission.FOLLOW |
                          Permission.COMMENT |
                          Permission.WRITE_ARTICLES |
                          Permission.MODERATE_COMMENTS, False),
            'Administrator': (0xff, False)
        }
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.permissions = roles[r][0]
            role.default = roles[r][1]
            db.session.add(role)
        db.session.commit()

    def __repr__(self):
        return '<Role %r>' % self.name


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    password_hash = db.Column(db.String(128))
    _confirmed = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(64))
    location = db.Column(db.String(64))
    about_me = db.Column(db.Text())
    member_since = db.Column(db.DateTime(), default=datetime.utcnow)
    last_seen = db.Column(db.DateTime(), default=datetime.utcnow)
    avatar_hash = db.Column(db.String(32))
    auth_token = db.Column(db.String(128), unique=True, index=True)
    last_failed_login_attempt = db.Column(db.DateTime(),
                                          default=datetime.utcnow)
    failed_login_attempts = db.Column(db.Integer, default=0)
    _locked = db.Column(db.Boolean, default=False)
    _enabled = db.Column(db.Boolean, default=True)

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config['APP_ADMIN']:
                self.role = Role.query.filter_by(permissions=0xff).first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()
        self.update_avatar_hash()
        self.update_auth_token()

    @staticmethod
    def can_register():
        if not current_app.config['APP_ALLOW_NEW_USERS']:
            return False
        else:
            if not current_app.config['APP_MAX_USERS']:
                return True
            else:
                return (
                    db.session.query(User).count() <
                        current_app.config['APP_MAX_USERS']
                )

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)
        self.update_auth_token()

    def verify_password(self, password):
        if not AccountPolicy.LOCKOUT_POLICY_ENABLED:
            if check_password_hash(self.password_hash, password):
                return True
            else:
                return False
        if self.locked or not self.enabled:
            return False
        if check_password_hash(self.password_hash, password):
            self.last_failed_login_attempt = None
            self.failed_login_attempts = 0
            return True
        if self.last_failed_login_attempt:
            if ((datetime.utcnow() - self.last_failed_login_attempt) >
                    AccountPolicy.RESET_THRESHOLD_AFTER):
                self.failed_login_attempts = 0
        self.last_failed_login_attempt = datetime.utcnow()
        self.failed_login_attempts += 1
        if self.failed_login_attempts == AccountPolicy.LOCKOUT_THRESHOLD:
            self.locked = True
        return False

    @property
    def confirmed(self):
        return self._confirmed

    @confirmed.setter
    def confirmed(self, confirmed):
        if confirmed and not self._confirmed:
            self._confirmed = True
        elif not confirmed and self._confirmed:
            self._confirmed = False

    @property
    def locked(self):
        return self._locked

    @locked.setter
    def locked(self, locked):
        if locked and not self._locked:
            self._locked = True
            # Invalidate sessions and remember cookies.
            self.randomize_auth_token()
        elif not locked and self._locked:
            self._locked = False
            self.failed_login_attempts = 0
            self.last_failed_login_attempt = None

    @property
    def enabled(self):
        return self._enabled

    @enabled.setter
    def enabled(self, enabled):
        if enabled and not self._enabled:
            self._enabled = True

        elif not enabled and self._enabled:
            self._enabled = False
            # Invalidate sessions and remember cookies.
            self.randomize_auth_token()

    def generate_confirmation_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm': self.id})

    def confirm(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return False
        except BadSignature:
            return False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        return True

    def generate_reset_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'reset': self.id})

    def reset_password(self, token, new_password):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return False
        except BadSignature:
            return False
        if data.get('reset') != self.id:
            return False
        self.password = new_password
        return True

    def generate_email_change_token(self, new_email, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'change_email': self.id, 'new_email': new_email})

    def change_email(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return False
        except BadSignature:
            return False
        if data.get('change_email') != self.id:
            return False
        new_email = data.get('new_email')
        if new_email is None:
            return False
        if self.query.filter_by(email=new_email).first() is not None:
            return False
        self.email = new_email
        self.update_avatar_hash()
        self.update_auth_token()
        return True

    def change_username(self, username):
        self.username = username
        self.update_auth_token()

    def can(self, permissions):
        return self.role is not None and \
            (self.role.permissions & permissions) == permissions

    def is_administrator(self):
        return self.can(Permission.ADMINISTER)

    def ping(self):
        self.last_seen = datetime.utcnow()

    def gravatar(self, size=100, default='identicon', rating='g'):
        if request.is_secure:
            url = 'https://secure.gravatar.com/avatar'
        else:
            url = 'http://www.gravatar.com/avatar'
        hash = self.avatar_hash or self.generate_avatar_hash()
        return '{url}/{hash}?s={size}&d={default}&r={rating}'.format(
            url=url, hash=hash, size=size, default=default, rating=rating)

    def generate_avatar_hash(self):
        if self.email is not None:
            return hashlib.md5(self.email.encode('utf-8')).hexdigest()
        return None

    def update_avatar_hash(self):
        self.avatar_hash = self.generate_avatar_hash()

    def generate_auth_token(self):
        if (self.email is not None and self.username is not None and
                self.password_hash is not None):
            return make_secure_token(self.email, self.username,
                                     self.password_hash)
        return None

    def randomize_auth_token(self):
        self.auth_token = make_secure_token(
            generate_password_hash(current_app.config['SECRET_KEY']))

    def update_auth_token(self):
        self.auth_token = self.generate_auth_token()

    def verify_auth_token(self, token):
        return token == self.auth_token

    # Returns a signed version of auth_token for Flask-Login's remember cookie.
    def get_auth_token(self):
        s = Signer(current_app.config['SECRET_KEY'])
        return s.sign(self.auth_token)

    def __repr__(self):
        return '<User %r>' % self.username


class AnonymousUser(AnonymousUserMixin):
    def can(self, permissions):
        return False

    def is_administrator(self):
        return False

login_manager.anonymous_user = AnonymousUser


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@login_manager.token_loader
def load_user_from_signed_token(signed_token):
    s = Signer(current_app.config['SECRET_KEY'])
    auth_token = None
    try:
        auth_token = s.unsign(signed_token)
    except:
        pass
    if auth_token:
        user = User.query.filter_by(auth_token=auth_token).first()
        if user:
            session['auth_token'] = user.auth_token
            return user
    # This causes Flask-Login to clear the "remember me" cookie. This could
    # break if Flask-Login's internal implementation changes. A better way
    # should be implemented. Perhaps install an after_request hook.
    session['remember'] = 'clear'
    return None
