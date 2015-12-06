from functools import wraps
from flask import abort
from flask.ext.login import current_user, fresh_login_required
from .models import Permission


def permission_required(permission):
    """Prevents access from anyone but those with the specified permission.

    If not authenticated, the user is allowed to authenticate. If the user is
    not of the required permission level, 403 is returned.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.can(permission):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def admin_required(f):
    """Prevents access from anyone but administrators.

    If not authenticated, the user is allowed to authenticate. If the user
    is not an administrator, 403 is returned.
    """
    return permission_required(Permission.ADMINISTER)(f)


def fresh_admin_required(f):
    """Prevents access from anyone but fresh administrators.

    If not authenticated, the user is allowed to authenticate. If the user
    is not an administrator, 403 is returned. If the user is already
    authenticated and is an administrator, but they are stale (logged in from
    a remember cookie), they will have to reauthenticate.
    """
    return fresh_login_required(admin_required(f))


def permission_or_404(permission):
    """Returns 404 to anyone but those with the specified permission.

    If not authenticated, the user will get a 404. If the user is authenticated
    but is not of the required permission level, the user will get a 404.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.can(permission):
                abort(404)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def admin_or_404(f):
    """Returns 404 to anyone but administrators.

    If not authenticated, the user will get a 404. If the user is authenticated
    but is not an administrator, the user will get a 404.
    """
    return permission_or_404(Permission.ADMINISTER)(f)


def fresh_admin_or_404(f):
    """Returns 404 to anyone but fresh administrators.

    If not authenticated, the user will get a 404. If the user is authenticated
    but is not an administrator, the user will get a 404. If the user is an
    administrator, but they are stale (logged in from a remember cookie),
    they will have to reauthenticate.
    """
    return admin_or_404(fresh_login_required(f))
