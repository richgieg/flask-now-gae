from urlparse import urlparse
from flask import current_app, request, url_for, redirect
from flask.ext.login import current_user
from flask.ext.wtf import Form
from wtforms import StringField, PasswordField, BooleanField, SubmitField, \
    HiddenField, SelectField
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from .. import RedirectForm
from .helpers import verify_password
from .models import Invite, Role, User


class LoginForm(RedirectForm):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                             Email()])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')


class ReauthenticationForm(RedirectForm):
    password = PasswordField('Password', validators=[Required()])
    submit = SubmitField('Submit')

    def validate_password(self, field):
        if not verify_password(current_user, field.data):
            raise ValidationError('Invalid password')


class RegistrationForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                           Email()])
    username = StringField('Username', validators=[
        Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                          'Usernames must have only letters, '
                                          'numbers, dots or underscores')])
    password = PasswordField('Password', validators=[Length(8, 64),
        Required(), EqualTo('password2', message='Passwords must match')])
    password2 = PasswordField('Confirm password', validators=[Required()])
    submit = SubmitField('Register')

    def validate_email(self, field):
        if User.query().filter(User.email == field.data).get():
            raise ValidationError('Email already registered')
        # If open registration is disabled, there is at least one registered
        # user, and the given email address is not on the pending invites
        # list, raise ValidationError.
        if (not current_app.config['APP_OPEN_REGISTRATION'] and
            User.query().count() > 0 and not Invite.is_pending(field.data)):
            raise ValidationError('Not on the invitation list')

    def validate_username(self, field):
        if User.query().filter(User.username == field.data).get():
            raise ValidationError('Username already in use')


class ChangeUsernameForm(RedirectForm):
    username = StringField('New Username', validators=[
        Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                          'Usernames must have only letters, '
                                          'numbers, dots or underscores')])
    password = PasswordField('Password', validators=[Required()])
    submit = SubmitField('Update Username')

    def validate_username(self, field):
        if User.query().filter(User.username == field.data).get():
            raise ValidationError('Username already in use')

    def validate_password(self, field):
        if not verify_password(current_user, field.data):
            raise ValidationError('Invalid password')


class ChangePasswordForm(RedirectForm):
    current_password = PasswordField('Current Password', validators=[Required()])
    password = PasswordField('New Password', validators=[Length(8, 64),
        Required(), EqualTo('password2', message='Passwords must match')])
    password2 = PasswordField('Confirm New Password', validators=[Required()])
    submit = SubmitField('Update Password')

    def validate_current_password(self, field):
        if not verify_password(current_user, field.data):
            raise ValidationError('Invalid password')


class PasswordResetRequestForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                             Email()])
    submit = SubmitField('Reset Password')


class PasswordResetForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                             Email()])
    password = PasswordField('New Password', validators=[Length(8, 64),
        Required(), EqualTo('password2', message='Passwords must match')])
    password2 = PasswordField('Confirm Password', validators=[Required()])
    submit = SubmitField('Reset Password')

    def validate_email(self, field):
        if User.query().filter(User.email == field.data).get() is None:
            raise ValidationError('Unknown email address')


class ChangeEmailForm(RedirectForm):
    email = StringField('New Email', validators=[Required(), Length(1, 64),
                                                 Email()])
    password = PasswordField('Password', validators=[Required()])
    submit = SubmitField('Update Email Address')

    def validate_email(self, field):
        if User.query().filter(User.email == field.data).get():
            raise ValidationError('Email already registered')

    def validate_password(self, field):
        if not verify_password(current_user, field.data):
            raise ValidationError('Invalid password')


class DeactivationForm(Form):
    password = PasswordField('Password', validators=[Required()])
    submit = SubmitField('Deactivate')

    def validate_password(self, field):
        if not verify_password(current_user, field.data):
            raise ValidationError('Invalid password')
