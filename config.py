# HERE WE GONNA PUT ALL OUR CONFIGURATION FOR THIS APP
# This file help us when with need to configure the app for different environments, such as development, testing or
# production and set its own configuration from here

import os  # WE NEED THE OS MODULE FOR SECURITY

basedir = os.path.abspath(os.path.dirname(__file__))  # WE ASSIGN THE PATH TO OUR BASEDIR


class Config:  # CREATED THE MAIN CONFIG CLASS
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'r;6VM2.yssk{ZT{BhM9fW2twfToekw/jtfg6}e9j6NCz4%*3iV6FHFZ++kwkgNBK'  # DATABASE [TODO: CHANGE THE SECRET KEY!!!]
    SQLALCHEMY_TRACK_MODIFICATIONS = False  # DATABASE
    MAIL_SERVER = 'smtp.gmail.com'  # SERVER MAIL TO USE GMAIL
    MAIL_PORT = 587  # EMAIL
    MAIL_USE_TLS = True  # SECURITY ENCRYPTION EMAIL
    MAIL_USERNAME = 'kazevtrinid@gmail.com'  # THE SENDER EMAIL
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')  # THE PASSWORD PASSING WITH OS
    APP_MAIL_SUBJECT_PREFIX = '[MAIL]'  # PREFIX
    APP_MAIL_SENDER = 'kazevtrinid@gmail.com'  # ADMIN MAIL
    APP_ADMIN = 'kevingtz0907@gmail.com'  # ADMIN

    @staticmethod
    def init_app(app):  # METHOD USE TO INIT THE APP
        pass


# Postgres Config list

POSTGRES_TEST = {
    'user': os.environ.get('DB_USER'),
    'pw': os.environ.get('DB_PASSWORD'), # [TODO] Change this to env variable
    'host': os.environ.get('DB_HOST'),
    'port': '5432',
    'db': os.environ.get('DB_NAME')
}

POSTGRES_DEV = {
    'user': os.environ.get('DB_USER'),
    'pw': os.environ.get('DB_PASSWORD'), # [TODO] Change this to env variable
    'host': os.environ.get('DB_HOST'),
    'port': '5432',
    'db': os.environ.get('DB_NAME')
}


# THE DIFFERENT CONFIGURATION CLASSES

class DevelopmentConfig(Config):  # DEVELOPMENT CONFIG
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or \
                              'postgresql+psycopg2://{user}:{pw}@{url}/{db}'.format(user=POSTGRES_DEV['user'],
                                                                                    pw=POSTGRES_DEV['pw'],
                                                                                    url=POSTGRES_DEV['host'],
                                                                                    db=POSTGRES_DEV[
                                                                                        'db'])  # THIS NEED A SET OF CONFIGURATION VARIABLES
    DEBUG = True



class TestingConfig(Config):  # TEST CONFIG
    # TESTING = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or \
                              'postgresql+psycopg2://{user}:{pw}@{url}/{db}'.format(user=POSTGRES_TEST['user'],
                                                                                    pw=POSTGRES_TEST['pw'],
                                                                                    url=POSTGRES_TEST['host'],
                                                                                    db=POSTGRES_TEST[
                                                                                        'db'])  # THIS NEED A SET OF CONFIGURATION VARIABLES


class ProductionConfig(Config):  # PRODUCTION CONFIG
    DEBUG = False



# HERE WE ASSIGN THE DIFFERENT CLASSES TO A DICTIONARY IN ORDER TO USE EACH CONFIG CLASS
config = {
    'testing': TestingConfig,
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': TestingConfig
}
