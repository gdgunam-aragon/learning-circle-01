from flask import Flask
from flask_mail import Mail
from flask_moment import Moment
from config import config
from flask_sqlalchemy import SQLAlchemy


mail = Mail()
moment = Moment()
db = SQLAlchemy()


def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config[config_name])  # PASSING THE CONFIG NAME IN ORDER TO THE CONFIG YOU WANNA USE
    config[config_name].init_app(app)

    # HERE WE INITIALIZE THE EXTENSION PASSING THE INSTANCE OF THE APP
    mail.init_app(app)
    moment.init_app(app)
    db.init_app(app)

    return app