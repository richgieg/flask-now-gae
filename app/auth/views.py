from datetime import datetime
from flask import render_template, redirect, request, url_for, session, \
    make_response, current_app, abort
from flask.ext.login import login_user, logout_user, login_required, \
    current_user, fresh_login_required, confirm_login, login_fresh
from .. import flash_it, login_manager, send_email
from ..main.models import Profile
from . import auth
from .decorators import authenticated_or_404, needs_reauth_or_404, \
    anonymous_or_404, needs_to_confirm_or_404, anonymous_or_go_home
from .forms import LoginForm, RegistrationForm, ChangePasswordForm, \
    PasswordResetRequestForm, PasswordResetForm, ChangeEmailForm, \
    ChangeUsernameForm, ReauthenticationForm, DeactivationForm
from .helpers import verify_password
from .messages import Messages
from .models import Invite, Role, User


# Set Flask-Login flash messages.
login_manager.login_message = Messages.LOGIN_REQUIRED[0]
login_manager.login_message_category = Messages.LOGIN_REQUIRED[1]
login_manager.needs_refresh_message = Messages.REFRESH_REQUIRED[0]
login_manager.needs_refresh_message_category = Messages.REFRESH_REQUIRED[1]


@auth.before_app_request
def before_request():
    if current_user.is_authenticated:
        if not current_user.verify_auth_token(session.get('auth_token')):
            logout_user()
            flash_it(Messages.SESSION_EXPIRED)
            return redirect(url_for('auth.login'))
        if (not current_user.confirmed and
                (not request.endpoint or request.endpoint[:5] != 'auth.') and
                request.endpoint != 'static'):
            return redirect(url_for('auth.unconfirmed'))
        current_user.ping()
        if not current_user.active:
            current_user.active = True
            flash_it(Messages.ACCOUNT_REACTIVATED)
    elif (User.query().count() == 0 and request.endpoint != 'auth.register' and
            not User.is_registration_in_memcache()):
        flash_it(Messages.INITIAL_REGISTRATION)
        return redirect(url_for('auth.register'))


@auth.after_app_request
def after_request(response):
    if session.get('_disabled', None):
        logout_user()
        return make_response(redirect(url_for('auth.disabled')))
    if session.get('_locked', None):
        logout_user()
        return make_response(redirect(url_for('auth.locked')))
    return response


@auth.route('/locked')
def locked():
    if session.pop('_locked', None):
        return render_template('auth/locked.html')
    return redirect(url_for('auth.login'))


@auth.route('/disabled')
def disabled():
    if session.pop('_disabled', None):
        session.pop('_locked', None)
        return render_template('auth/disabled.html')
    return redirect(url_for('auth.login'))


@auth.route('/unconfirmed')
@needs_to_confirm_or_404
def unconfirmed():
    return render_template('auth/unconfirmed.html')


@auth.route('/login', methods=['GET', 'POST'])
@anonymous_or_404
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query().filter(User.email == form.email.data).get()
        if user is not None and verify_password(user, form.password.data):
            login_user(user, form.remember_me.data)
            session['auth_token'] = user.auth_token
            return form.redirect('main.index')
        flash_it(Messages.INVALID_CREDENTIALS)
    return render_template('auth/login.html', form=form)


@auth.route('/reauthenticate', methods=['GET', 'POST'])
@needs_reauth_or_404
def reauthenticate():
    form = ReauthenticationForm()
    if form.validate_on_submit():
        confirm_login()
        return form.redirect('main.index')
    return render_template('auth/reauthenticate.html', form=form)


@auth.route('/logout')
@authenticated_or_404
def logout():
    logout_user()
    flash_it(Messages.LOG_OUT)
    return redirect(url_for('main.index'))


@auth.route('/register', methods=['GET', 'POST'])
@anonymous_or_go_home
def register():
    # If open registration is disabled, there are no pending registration
    # invites, and there is at least one registered user, return 404.
    if (not current_app.config['APP_OPEN_REGISTRATION'] and
        not Invite.pending_invites() and User.query().count() > 0):
        abort(404)
    # TODO: Fix possible synchronization issue. If the current number of users
    # is one less than APP_MAX_USERS, and two users happen to post back the
    # completed registration form at the exact same time and both move beyond
    # this check, is it possible that the number of users could be one greater
    # than APP_MAX_USERS?
    # TODO Update: A memcache-based solution could work here
    if not User.can_register():
        return render_template('auth/register_disabled.html')
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User.register(form.email.data, form.username.data,
                             form.password.data)
        # If open registration is disabled, the user must have been invited
        # to register, so email a confirmation to the person who invited them,
        # then remove their invite.
        if not current_app.config['APP_OPEN_REGISTRATION']:
            Invite.notify_inviter(user.email)
            Invite.remove(user.email)
        token = user.generate_confirmation_token()
        send_email(user.email, 'Confirm Your Account',
                   'auth/email/confirm', user=user, token=token)
        flash_it(Messages.CONFIRM_ACCOUNT)
        return redirect(url_for('main.index'))
    return render_template('auth/register.html', form=form)


@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash_it(Messages.ACCOUNT_CONFIRMED)
    else:
        flash_it(Messages.INVALID_CONFIRMATION_LINK)
    return redirect(url_for('main.index'))


@auth.route('/confirm')
@needs_to_confirm_or_404
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, 'Confirm Your Account',
               'auth/email/confirm', user=current_user, token=token)
    flash_it(Messages.CONFIRM_ACCOUNT)
    return redirect(url_for('main.index'))


@auth.route('/change-username', methods=['GET', 'POST'])
@login_required
def change_username():
    form = ChangeUsernameForm()
    if form.validate_on_submit():
        current_user.change_username(form.username.data)
        session['auth_token'] = current_user.auth_token
        flash_it(Messages.USERNAME_UPDATED)
        return redirect(url_for('main.index'))
    return render_template("auth/change_username.html", form=form)


@auth.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        current_user.password = form.password.data
        current_user.put()
        session['auth_token'] = current_user.auth_token
        flash_it(Messages.PASSWORD_UPDATED)
        return form.redirect('main.index')
    return render_template("auth/change_password.html", form=form)


@auth.route('/reset', methods=['GET', 'POST'])
@anonymous_or_404
def password_reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = User.query().filter(User.email == form.email.data).get()
        if user:
            if not user.enabled:
                flash_it(Messages.PASSWORD_RESET_REQUEST_DISABLED_ACCOUNT)
            else:
                token = user.generate_reset_token()
                send_email(user.email, 'Reset Your Password',
                           'auth/email/reset_password',
                           user=user, token=token,
                           next=request.args.get('next'))
                flash_it(Messages.PASSWORD_RESET_REQUEST)
        else:
            # This is just to trick anyone guessing email addresses.
            flash_it(Messages.PASSWORD_RESET_REQUEST)
        return redirect(url_for('main.index'))
    return render_template('auth/reset_password.html', form=form)


@auth.route('/reset/<token>', methods=['GET', 'POST'])
def password_reset(token):
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = PasswordResetForm()
    if form.validate_on_submit():
        user = User.query().filter(User.email == form.email.data).get()
        if user is None:
            return redirect(url_for('main.index'))
        if user.reset_password(token, form.password.data):
            flash_it(Messages.PASSWORD_UPDATED)
            if user.locked:
                user.locked = False
                flash_it(Messages.ACCOUNT_UNLOCKED)
            return redirect(url_for('auth.login'))
        else:
            flash_it(Messages.INVALID_PASSWORD_RESET_LINK)
            return redirect(url_for('main.index'))
    return render_template('auth/reset_password.html', form=form)


@auth.route('/change-email', methods=['GET', 'POST'])
@login_required
def change_email_request():
    form = ChangeEmailForm()
    if form.validate_on_submit():
        new_email = form.email.data
        token = current_user.generate_email_change_token(new_email)
        send_email(new_email, 'Confirm Your Email Address',
                   'auth/email/change_email',
                   user=current_user, token=token)
        flash_it(Messages.EMAIL_CHANGE_REQUEST)
        return form.redirect('main.index')
    return render_template('auth/change_email.html', form=form)


@auth.route('/change-email/<token>')
@fresh_login_required
def change_email(token):
    if current_user.change_email(token):
        session['auth_token'] = current_user.auth_token
        flash_it(Messages.EMAIL_UPDATED)
    else:
        flash_it(Messages.INVALID_CONFIRMATION_LINK)
    return redirect(url_for('main.index'))


@auth.route('/deactivate', methods=['GET', 'POST'])
@authenticated_or_404
def deactivate():
    form = DeactivationForm()
    if form.validate_on_submit():
        current_user.active = False
        logout_user()
        flash_it(Messages.ACCOUNT_DEACTIVATED)
        return redirect(url_for('main.index'))
    return render_template('auth/deactivate.html', form=form)
