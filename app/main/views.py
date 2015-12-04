from flask import render_template, redirect, url_for, abort
from flask.ext.login import login_required, current_user, fresh_login_required
from .. import flash_it
from ..auth.decorators import admin_required
from ..auth.models import Role, User
from . import main
from .forms import EditProfileForm, EditProfileAdminForm
from .messages import Messages


@main.route('/')
def index():
    return render_template('index.html')


@main.route('/user/<username>')
def user(username):
    user = User.query().filter(User.username == username).get()
    if not user:
        abort(404)
    return render_template('user.html', user=user)


@main.route('/users')
def users():
    if current_user.is_administrator():
        users = User.query().order(User.username).fetch()
    else:
        users = (
            User.query()
                .filter(User.pvt__confirmed == True)
                .order(User.username)
                .fetch()
        )
    return render_template('users.html', users=users)


@main.route('/edit-profile', methods=['GET', 'POST'])
@fresh_login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.location = form.location.data
        current_user.about_me = form.about_me.data
        current_user.put()
        flash_it(Messages.PROFILE_UPDATED)
        return redirect(url_for('.user', username=current_user.username))
    form.name.data = current_user.name
    form.location.data = current_user.location
    form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', form=form)


@main.route('/edit-profile/<int:id>', methods=['GET', 'POST'])
@fresh_login_required
@admin_required
def edit_profile_admin(id):
    user = User.get(id)
    if not user:
        abort(404)
    form = EditProfileAdminForm(user=user)
    if form.validate_on_submit():
        user.email = form.email.data
        user.username = form.username.data
        user.confirmed = form.confirmed.data
        user.enabled = form.enabled.data
        user.locked = form.locked.data
        user.role = Role.get(form.role.data)
        user.name = form.name.data
        user.location = form.location.data
        user.about_me = form.about_me.data
        user.put()
        flash_it(Messages.OTHER_PROFILE_UPDATED)
        return redirect(url_for('.user', username=user.username))
    form.email.data = user.email
    form.username.data = user.username
    form.enabled.data = user.enabled
    form.locked.data = user.locked
    form.confirmed.data = user.confirmed
    form.role.data = user.role.id
    form.name.data = user.name
    form.location.data = user.location
    form.about_me.data = user.about_me
    return render_template('edit_profile_admin.html', form=form, user=user)
