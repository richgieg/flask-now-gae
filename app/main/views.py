from flask import render_template, redirect, url_for, abort
from flask.ext.login import login_required, current_user, fresh_login_required
from .. import flash_it
from ..auth.decorators import admin_required
from ..auth.models import Role, User
from . import main
from .forms import EditProfileForm
from .messages import Messages


@main.route('/')
def index():
    return render_template('main/index.html')


@main.route('/profile/<username>')
def profile(username):
    user = User.query().filter(User.username == username).get()
    if not user:
        abort(404)
    return render_template('main/profile.html', user=user,
                           profile=user.get_profile())


@main.route('/edit-profile', methods=['GET', 'POST'])
@fresh_login_required
def edit_profile():
    form = EditProfileForm()
    profile = current_user.get_profile()
    if form.validate_on_submit():
        profile.name = form.name.data
        profile.location = form.location.data
        profile.about_me = form.about_me.data
        profile.put()
        flash_it(Messages.PROFILE_UPDATED)
        return redirect(url_for('.profile', username=current_user.username))
    form.name.data = profile.name
    form.location.data = profile.location
    form.about_me.data = profile.about_me
    return render_template('main/edit_profile.html', form=form)
