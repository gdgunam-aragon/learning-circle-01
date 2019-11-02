from flask import Flask
from flask_login import LoginManager
from flask_bootstrap import Bootstrap
from flask_mail import Mail
from flask_moment import Moment
from flask_pagedown import PageDown
from config import config
from flask_sqlalchemy import SQLAlchemy


bootstrap = Bootstrap()
mail = Mail()
moment = Moment()
db = SQLAlchemy()
pagedown = PageDown()


login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'auth.login'
login_manager.login_view = 'api.login'


def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config[config_name])  # PASSING THE CONFIG NAME IN ORDER TO THE CONFIG YOU WANNA USE
    config[config_name].init_app(app)

    # HERE WE INITIALIZE THE EXTENSION PASSING THE INSTANCE OF THE APP
    bootstrap.init_app(app)
    mail.init_app(app)
    moment.init_app(app)
    db.init_app(app)
    login_manager.init_app(app)
    pagedown.init_app(app)

    # IMPORTING THE 'MAIN_BLUEPRINT'
    from .main import main as main_blueprint  # AVOIDING THE CIRCULAR DEPENDENCIES
    app.register_blueprint(main_blueprint)

    # IMPORTING THE 'AUTH_BLUEPRINT'
    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/auth')

    from .api import api as api_blueprint
    app.register_blueprint(api_blueprint, url_prefix='/api/v1')

    from .api_ops import api_ops as api_blueprint
    app.register_blueprint(api_blueprint, url_prefix='/api_ops/v1')

    return app