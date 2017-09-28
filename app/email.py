# SMPT automatic sending of emails with flask-mail
# -*- coding: utf-8 -*-
from threading import Thread
from flask import current_app, render_template
from flask_mail import Message
from . import mail


def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)


def send_email(to, subject, template, **kwargs):
    """ In order to send non-ascii chars in emails add
    encoding as utf8. msg.body = 'здравей'.encode('utf8')
    """
    app = current_app._get_current_object()
    msg = Message(app.config['THE_LIBRARY_SUBJECT_PREFIX'] + ' ' + subject,
                  sender=app.config['THE_LIBRARY_SENDER'], recipients=[to],
                  charset='utf8')
    msg.body = render_template(template + '.txt', **kwargs).encode('utf8')
    msg.html = render_template(template + '.html', **kwargs).encode('utf8')
    thr = Thread(target=send_async_email, args=[app, msg])
    thr.start()
    return thr
