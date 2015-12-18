from flask import session

from .controllers import AuthController


def verify_password(user, password):
    is_valid_password = AuthController.verify_password(user, password)
    if user.locked:
        session['_locked'] = True
    if not user.enabled:
        session['_disabled'] = True
    return is_valid_password
