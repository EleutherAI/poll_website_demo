from flask import Flask

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_admin import Admin
from flask_bootstrap import Bootstrap

from config import Config

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bootstrap = Bootstrap(app)

login = LoginManager(app)
login.login_view = 'login'

app.config['FLASK_ADMIN_SWATCH'] = 'cerulean'
admin = Admin(app, name='Eleuther Admin Template', template_mode='bootstrap3')

import models

