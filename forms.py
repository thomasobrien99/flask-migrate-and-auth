from flask_wtf import Form
from wtforms import StringField, PasswordField, IntegerField

from wtforms.validators import DataRequired, Length


class NewUserForm(Form):
	username = StringField('username', validators=[ DataRequired() ])
	password = PasswordField('password', validators=[ DataRequired(), Length(min=4)])

class LoginForm(Form):
	username = StringField('username', validators=[ DataRequired() ])
	password = PasswordField('password', validators=[ DataRequired(), Length(min=4)])
