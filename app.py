import os
from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_wtf import CsrfProtect
from functools import wraps

from forms import NewUserForm, LoginForm


app = Flask(__name__)
CsrfProtect(app)
bcrypt = Bcrypt(app)


app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://localhost/learn-flask-migrate-2'
app.config['SQLALCHEMY_TRACK_MODIFCATIONS'] = False


app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')


db = SQLAlchemy(app)

def login_required(f):
	@wraps(f)
	def inner(*args, **kwargs):
	  if not(session.get('user_id')):
	  	  return redirect(url_for('login'))
	  return f(*args, **kwargs)
	return inner

class User(db.Model):
	__tablename__ = 'users'
	id = db.Column(db.Integer, primary_key = True)
	username = db.Column(db.Text, nullable = False)
	password = db.Column(db.Text, nullable = False)

	def __init__(self, username, password):
		self.username = username
		self.password = bcrypt.generate_password_hash(password).decode('utf-8')

@app.route('/')
@app.route('/users')
@login_required
def index_user():
	users = User.query.all()
	return render_template('index.html', users=users)

@app.route('/users/new')
def new_user():
	form = NewUserForm()
	return render_template('new.html', form=form)

@app.route('/users', methods=["POST"])
def create_user():
	form = NewUserForm()
	if form.validate_on_submit():
	  user = User(form.username.data, form.password.data)
	  db.session.add(user)
	  db.session.commit()
	  flash('You Created A User!')
	  return redirect(url_for('index_user'))
	return render_template('new.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
	error = None
	form = LoginForm()
	# Did the form submit??
	if form.validate_on_submit():
			# check for the username
			found_user = User.query.filter_by(username=form.username.data).first()
			if found_user:
				# check for the password
				is_authenticated = bcrypt.check_password_hash(found_user.password, form.password.data)
				if is_authenticated:
					session['user_id'] = found_user.id
					return redirect(url_for('index_user'))
				else:
					error = "Invalid Username/Password"
	else:
		error = "Invalid Username/Password"
	return render_template('login.html', form=form, error=error)

@app.route('/logout')
def logout():
	session.pop('user_id', None)
	return redirect(url_for('login'))
if __name__ == '__main__':
	app.run(debug=True, port=3000)