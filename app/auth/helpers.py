from flask import session


def verify_password(user, password):
    is_valid_password = user.verify_password(password)
    if user.locked:
        session['_locked'] = True
    if not user.enabled:
        session['_disabled'] = True
    return is_valid_password
