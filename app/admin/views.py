from babel.dates import format_timedelta
from flask import abort, current_app, redirect, render_template, url_for
from flask.ext.login import current_user
from .. import flash_it, send_email
from ..auth.decorators import fresh_admin_required, fresh_admin_or_404
from ..auth.models import Invite, Role, User
from . import admin
from .forms import EditUserForm, InviteUserForm
from .messages import Messages


@admin.route('/')
@fresh_admin_required
def index():
    return render_template('admin/index.html')


@admin.route('/users')
@fresh_admin_or_404
def users():
    users = User.get_users(order=User.email)
    roles = Role.get_dict()
    return render_template('admin/users.html', users=users, roles=roles)


@admin.route('/user/<int:id>', methods=['GET', 'POST'])
@fresh_admin_or_404
def user(id):
    user = User.get(id)
    if not user:
        abort(404)
    form = EditUserForm(user=user)
    if form.validate_on_submit():
        user.email = form.email.data
        user.username = form.username.data
        user.confirmed = form.confirmed.data
        user.enabled = form.enabled.data
        user.locked = form.locked.data
        user.role = Role.get(form.role.data)
        user.put()
        flash_it(Messages.USER_UPDATED)
        return redirect(url_for('admin.user', id=user.id))
    form.email.data = user.email
    form.username.data = user.username
    form.enabled.data = user.enabled
    form.locked.data = user.locked
    form.confirmed.data = user.confirmed
    form.role.data = user.role.id
    return render_template('admin/user.html', form=form, user=user)


@admin.route('/invite', methods=['GET', 'POST'])
@fresh_admin_or_404
def invite_user():
    if current_app.config['APP_OPEN_REGISTRATION']:
        abort(404)
    form = InviteUserForm()
    expire = format_timedelta(current_app.config['APP_INVITE_TTL'],
                              locale='en_US')
    if form.validate_on_submit():
        email = form.email.data
        Invite.create(email)
        send_email(email, 'You\'ve Been Invited!', 'admin/email/invite',
                   inviter=current_user, email=email, expire=expire)
        flash_it(Messages.USER_INVITED)
        return form.redirect()
    return render_template('admin/invite_user.html', form=form, expire=expire)
