""" File that contains configuration settings needed by the
application.
"""
import os
basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ['SECRET_KEY']
    # SECRET_KEY = 'SECRET'
    SQLALCHEMY_COMMIT_ON_TEARDOWON = True
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    MAIL_SERVER = 'smtp.googlemail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    THE_LIBRARY_SUBJECT_PREFIX = '[The_Librarian]'
    THE_LIBRARY_SENDER = 'The Library Admin @ <library@example.com'
    THE_LIBRARY_ADMIN = os.environ.get("LIBRARY_ADMIN")
    THE_LIBRARY_POST_PER_PAGE = 10
    THE_LIBRARY_FOLLOWERS_PER_PAGE = 10
    THE_LIBRARY_COMMENTS_PER_PAGE = 10
    # need to change to environ
    OAUTH_CREDENTIALS = {
    'facebook': {
    'id': '1831381967192273',
    'secret' : 'c0e105c47531d2d58a1a1ef899c288b9'
    },
    'google' : {
    'id' : '1003654119130-8e7q6h264efdvfn7v6gi08iilj9fhmso.apps.googleusercontent.com',
    'secret' : 'BwSODsGC6odf1gOOZJ5rsOdb'
    }}
    # need to change to environ
    # TOP_LEVEL_DIR = '/home/infra/GitHub/The-Library'  # UNIX ENV
    TOP_LEVEL_DIR = 'C:\coding\Python\The-Library'  # Windows ENV
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    UPLOADS_DEFAULT_DEST = TOP_LEVEL_DIR + '\\app\\static\\img\\'
    UPLOADS_DEFAULT_URL = 'http://localhost:5000/static/img/'
    UPLOADED_IMAGES_DEST = TOP_LEVEL_DIR + '\\app\\static\\img\\'
    UPLOADED_IMAGES_URL = 'http://localhost:5000/static/img/'
    WHOOSH_BASE = os.path.join(basedir, 'search.db')
    MAX_SEARCH_RESULTS = 50
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
