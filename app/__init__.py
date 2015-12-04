from flask import current_app, flash, Flask, render_template
from flask.ext.bootstrap import Bootstrap
from flask.ext.moment import Moment
from flask.ext.login import LoginManager
from google.appengine.api import mail
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
