from functools import wraps
from flask import abort, redirect, url_for
from flask.ext.login import current_user, login_fresh
from .settings import Permission


def permission_or_403(permission):
    """Returns 403 if the user doesn't have the specified permission level.

    If not authenticated, 403 is returned. If the user is authenticated but is
    not of the required permission level, 403 is returned. Otherwise, they are
    allowed to access the decorated view.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.can(permission):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def permission_or_404(permission):
    """Returns 404 if the user doesn't have the specified permission level.

    If not authenticated, 404 is returned. If the user is authenticated but is
    not of the required permission level, 404 is returned. Otherwise, they are
    allowed to access the decorated view.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.can(permission):
                abort(404)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def permission_or_go_home(permission):
    """Redirects to home if user doesn't have the specified permission level.

    If not authenticated, the user is redirected to main.index. If the user is
    authenticated but is not of the required permission level, they are
    redirected to main.index. Otherwise, they are allowed to access the
    decorated view.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.can(permission):
                return redirect(url_for('main.index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def admin_or_403(f):
    """Returns 403 if the user is not an administrator.

    If not authenticated, 403 is returned. If the user is authenticated but is
    not an administrator, 403 is returned. Otherwise, they are allowed to
    access the decorated view.
    """
    return permission_or_403(Permission.ADMINISTER)(f)


def admin_or_404(f):
    """Returns 404 if the user is not an administrator.

    If not authenticated, 404 is returned. If the user is authenticated but is
    not an administrator, 404 is returned. Otherwise, they are allowed to
    access the decorated view.
    """
    return permission_or_404(Permission.ADMINISTER)(f)


def admin_or_go_home(f):
    """If not authenticated, the user is redirected to main.index. If the user
    is authenticated but is not an administrator, they are redirected to
    main.index. Otherwise, they are allowed to access the decorated view.
    """
    return permission_or_go_home(Permission.ADMINISTER)(f)


def authenticated_or_404(f):
    """Returns 404 if the user is not currently authenticated.

    This was specifically created to block the auth.login view if it's not
    needed. It may also be useful for hiding other views that shouldn't need
    to be accessed if the user isn't logged in.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(404)
        return f(*args, **kwargs)
    return decorated_function


def anonymous_or_404(f):
    """Returns 404 if the user is currently authenticated.

    This was specifically created to block the auth.register view if it's not
    needed. It may also be useful for hiding other views that shouldn't need
    to be accessed if the user is logged in.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            abort(404)
        return f(*args, **kwargs)
    return decorated_function


def needs_reauth_or_404(f):
    """Returns 404 if the user has no need to reauthenticate.

    Reauthentication is necessary if the user is currently authenticated and
    the session is stale (authenticated with remember cookie). If either of
    these conditions is false, 404 is returned. This was specifically created
    to block the auth.reauthenticate view if it's not needed.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or login_fresh():
            abort(404)
        return f(*args, **kwargs)
    return decorated_function


def needs_to_confirm_or_404(f):
    """Returns 404 if the user has no need to confirm their account.

    Confirmation is necessary if the user is currently authenticated and
    the the "confirmed" flag on their user entity is false. If either of
    these conditions is false, 404 is returned. This was specifically created
    to block the auth.unconfirmed view if it's not needed.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.confirmed:
            abort(404)
        return f(*args, **kwargs)
    return decorated_function
