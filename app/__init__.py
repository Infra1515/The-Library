# Application factory function - allows the selection of different configuration
# settings before the app is initialized.
from flask import Flask
from flask_bootstrap import Bootstrap
from flask_mail import Mail
from flask_moment import Moment
from flask_sqlalchemy import SQLAlchemy
from config import config

# Initializes the extensions without giving arguments to their
# constructors in order to be able to set different config parameters below

bootstrap = Bootstrap()
mail = Mail()
moment = Moment()
db = SQLAlchemy()

def create_app(config_name):
    """
        This function is the application factory. Takes as an argument the name
        of a configuration to use from the classes defined in cofig.py and
        constructs the app and the extensions.
    """
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)

    bootstrap.init_app(app)
    mail.init_app(app)
    moment.init_app(app)
    db.init_app(app)

# Blueprint registration
    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app
