""" File that contains configuration settings needed by the
application.
"""
import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_COMMIT_ON_TEARDOWON = True
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAIL_SERVER = 'smtp.googlemail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    THE_LIBRARY_SUBJECT_PREFIX = '[The_Librarian]'
    THE_LIBRARY_SENDER = 'The Library Admin @ <library@example.com'
    THE_LIBRARY_ADMIN = os.environ.get("LIBRARY_ADMIN")
    OAUTH_CREDENTIALS = {
    'facebook': {
    'id': '1831381967192273',
    'secret' : 'c0e105c47531d2d58a1a1ef899c288b9'
    },
    'google' : {
    'id' : '1003654119130-8e7q6h264efdvfn7v6gi08iilj9fhmso.apps.googleusercontent.com',
    'secret' : 'BwSODsGC6odf1gOOZJ5rsOdb'
    }
    UPLOAD_FOLDER = '/home/infra/GitHub/The-Library/app/static/uploads'
    ALLOWED_EXTENSIONS = 'set(['png', 'jpg', 'jpeg', 'gif'])'
}

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'data-dev.sqlite')


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'data-test.sqlite')


class ProductionConfig(Config):
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'data.sqlite')

config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,

    'default': DevelopmentConfig
}
