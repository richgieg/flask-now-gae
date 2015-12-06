from flask import current_app, request, url_for, redirect
from flask.ext.wtf import Form
from wtforms import StringField, PasswordField, BooleanField, SubmitField, \
    HiddenField, SelectField
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from .. import is_safe_redirect_url
from .models import Invite, Role, User


class RedirectForm(Form):
    next = HiddenField()

    def __init__(self, *args, **kwargs):
        Form.__init__(self, *args, **kwargs)
        if request.method == 'GET' and request.referrer != request.url:
            self.next.data = request.referrer

    def redirect(self, endpoint='main.index', **values):
        for target in request.args.get('next'), self.next.data:
            if target and is_safe_redirect_url(target):
                return redirect(target)
        return redirect(url_for(endpoint, **values))
