from urlparse import urlparse
from flask import current_app, flash, Flask, render_template, redirect, \
    request, url_for
from flask.ext.bootstrap import Bootstrap
from flask.ext.login import LoginManager
from flask.ext.moment import Moment
from flask.ext.wtf import Form
from google.appengine.api import mail
from wtforms import HiddenField
from config import config


bootstrap = Bootstrap()
moment = Moment()

login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.refresh_view = 'auth.reauthenticate'


def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)

    bootstrap.init_app(app)
    moment.init_app(app)
    login_manager.init_app(app)

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/auth')

    from .admin import admin as admin_blueprint
    app.register_blueprint(admin_blueprint, url_prefix='/admin')

    from .error import error as error_blueprint
    app.register_blueprint(error_blueprint)

    return app


def get_flash_category(css_class, heading):
    return { 'css_class': css_class, 'heading': heading }


class FlashCategory:
    SUCCESS = get_flash_category('alert-success', '')
    INFO = get_flash_category('alert-info', '')
    WARNING = get_flash_category('alert-warning', '')
    DANGER = get_flash_category('alert-danger', '')


def flash_it(message_structure):
    if message_structure:
        flash(*message_structure)


def send_email(to, subject, template, **kwargs):
    app = current_app._get_current_object()
    sender = app.config['APP_MAIL_SENDER']
    subject = app.config['APP_MAIL_SUBJECT_PREFIX'] + ' ' + subject
    body = render_template(template + '.txt', **kwargs)
    html = render_template(template + '.html', **kwargs)
    mail.send_mail(sender, to, subject, body, html=html)


def is_safe_redirect_url(target):
    """Assists in preventing open redirect attacks by checking URLs.

    Target URL is accepted as safe if its scheme (protocol) and
    netloc (hostname) fields match those of the current application.
    Target URL is also accepted as safe if its scheme and netloc fields
    are empty, since it's a relative link in the current application.
    Additionaly, the path field is checked for extra slashes which would
    signify a malformed URL. The motivation behind the check for extra
    slashes is because when the redirect URL is a phony relative URL such as
    "////google.com", a redirect is issued and in turn the browser issues
    a GET request for "//google.com", which causes the development server
    to issue a 301 redirect to "google.com". I've found that Nginx does not
    exhibit this behavior, but I figured the extra check couldn't hurt.

    Args:
        target: The redirect URL.

    Returns:
        True if the URL is determined to be safe.
    """
    host_url = urlparse(request.host_url)
    target_url = urlparse(target)
    if (target_url.scheme == host_url.scheme and
            target_url.netloc == host_url.netloc):
        return True
    if (not target_url.scheme and not target_url.netloc and
            '//' not in target_url.path):
        return True
    return False


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
