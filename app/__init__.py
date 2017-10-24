# Application factory function - allows the selection of different configuration
# settings before the app is initialized.
from flask import Flask
from flask_bootstrap import Bootstrap
from flask_mail import Mail
from flask_moment import Moment
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from config import config
from flask_uploads import UploadSet, IMAGES, configure_uploads

# Initializes the extensions without giving arguments to their
# constructors in order to be able to set different config parameters below

bootstrap = Bootstrap()
mail = Mail()
moment = Moment()
db = SQLAlchemy()
login_manager = LoginManager()
login_manager.session_protection = "strong"
login_manager.login_view = "auth.login"
images = UploadSet('images', IMAGES)
def create_app(config_name):
    """
        This function is the application factory. Takes as an argument the name
        of a configuration to use from the classes defined in config.py and
        constructs the app and the extensions.
    """
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)

    bootstrap.init_app(app)
    mail.init_app(app)
    moment.init_app(app)
    db.init_app(app)
    login_manager.init_app(app)
    configure_uploads(app, images)
# Blueprint registration
    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix = "/auth")

    return app
