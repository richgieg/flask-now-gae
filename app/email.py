from flask import current_app, render_template
from google.appengine.api import mail


def send_email(to, subject, template, **kwargs):
    app = current_app._get_current_object()
    sender = app.config['APP_MAIL_SENDER']
    subject = app.config['APP_MAIL_SUBJECT_PREFIX'] + ' ' + subject
    body = render_template(template + '.html', **kwargs)
    # msg.body = render_template(template + '.txt', **kwargs)
    # msg.html = render_template(template + '.html', **kwargs)
    mail.send_mail(sender, to, subject, body)
