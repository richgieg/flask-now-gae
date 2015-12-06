"""Flash message constants for auth package.

This module contains all of the string constants used for flash messages. The
attributes in the message classes should be tuples with two elements. The first
element is the message string. The second element is the message category. This
enables flash messages in each category to take on unique visual traits, by
passing a CSS class name behind the scenes. If you do not wish for a flash
message to be displayed for a particular event, set the attribute to None
instead of the standard tuple.

"""

from .. import FlashCategory


class Messages:
    ACCOUNT_CONFIRMED = (
        'Your account is confirmed',
        FlashCategory.SUCCESS
    )
    ACCOUNT_UNLOCKED = (
        'Your account is unlocked',
        FlashCategory.SUCCESS
    )
    CONFIRM_ACCOUNT = (
        'Check your email for confirmation instructions',
        FlashCategory.INFO
    )
    EMAIL_CHANGE_REQUEST = (
        'Confirmation instructions sent to the requested email',
        FlashCategory.INFO
    )
    EMAIL_UPDATED = (
        'Your email is updated',
        FlashCategory.SUCCESS
    )
    INITIAL_REGISTRATION = (
        'You must register your admin account',
        FlashCategory.INFO
    )
    INVALID_CONFIRMATION_LINK = (
        'This link is invalid or has expired',
        FlashCategory.DANGER
    )
    INVALID_CREDENTIALS = (
        'Bad username or password',
        FlashCategory.DANGER
    )
    INVALID_PASSWORD = (
        'Bad password',
        FlashCategory.DANGER
    )
    INVALID_PASSWORD_RESET_LINK = (
        'Password not updated due to invalid or expired token',
        FlashCategory.DANGER
    )
    LOG_OUT = (
        'You have logged out',
        FlashCategory.SUCCESS
    )
    LOGIN_REQUIRED = (
        'Log in to access this page',
        FlashCategory.INFO
    )
    PASSWORD_UPDATED = (
        'Your password is updated',
        FlashCategory.SUCCESS
        )
    PASSWORD_RESET_REQUEST = (
        'Check your email for password reset instructions',
        FlashCategory.INFO
    )
    PASSWORD_RESET_REQUEST_DISABLED_ACCOUNT = (
        'Password reset not allowed for disabled accounts',
        FlashCategory.INFO
    )
    REFRESH_REQUIRED = (
        'Verify your password to continue',
        FlashCategory.INFO
    )
    SESSION_EXPIRED = (
        'Your session has expired',
        FlashCategory.DANGER
    )
    USERNAME_UPDATED = (
        'Your username is updated',
        FlashCategory.SUCCESS
    )
