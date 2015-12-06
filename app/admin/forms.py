from flask import current_app, request, url_for, redirect
from flask.ext.wtf import Form
from wtforms import StringField, PasswordField, BooleanField, SubmitField, \
    HiddenField, SelectField
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from .. import RedirectForm
from ..auth.models import Invite, Role, User


class EditUserForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                             Email()])
    username = StringField('Username', validators=[
        Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                          'Usernames must have only letters, '
                                          'numbers, dots or underscores')])
    enabled = BooleanField('Enabled')
    active = BooleanField('Active')
    locked = BooleanField('Locked')
    confirmed = BooleanField('Confirmed')
    role = SelectField('Role', coerce=int)
    submit = SubmitField('Submit')

    def __init__(self, user, *args, **kwargs):
        super(EditUserForm, self).__init__(*args, **kwargs)
        self.role.choices = [(role.id, role.name)
                             for role in Role.all()]
        self.user = user

    def validate_email(self, field):
        if field.data != self.user.email and \
                User.query().filter(User.email == field.data).get():
            raise ValidationError('Email already registered')

    def validate_username(self, field):
        if field.data != self.user.username and \
                User.query().filter(User.username == field.data).get():
            raise ValidationError('Username already in use')

class InviteUserForm(RedirectForm):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                                 Email()])
    submit = SubmitField('Invite')

    def validate_email(self, field):
        if User.query().filter(User.email == field.data).get():
            raise ValidationError('Email already registered')
