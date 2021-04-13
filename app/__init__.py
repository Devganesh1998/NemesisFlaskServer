from flask import Flask
from config import app_config
from flask_migrate import Migrate
from .models import *

from .routes import auth as auth_blueprint

def create_app(config_name):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(app_config[config_name])
    app.config.from_pyfile('config.py')

    db.init_app(app)
    migrate = Migrate(app, db)

    app.register_blueprint(auth_blueprint, url_prefix='/auth')

    return app
