from flask import Flask, request, render_template, json, jsonify, Response, flash, redirect, url_for, send_file

from werkzeug.urls import url_parse

from flask_login import current_user, login_user, login_required, logout_user

from forms import LoginForm
from forms import ResetPasswordRequestForm
from forms import ResetPasswordForm
from forms import ExampleForm

from emailer import send_password_reset_email

from app import app
from app import db
from app import admin

from models import User, Bmk

from flask_admin.contrib.sqla import ModelView

# Index and 404
# ===================================================================
@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# Example for bmk
# ===================================================================

# This first route returns a template with a text box and button that 
# when clicked will call the simple-example-api and save this info to the 
# database.

# I commented out @login_required to make testing easier

@app.route('/simple-example', methods=['GET', 'POST'])
@login_required
def simple_example_view():
    print(current_user)

    form = ExampleForm()

    if form.validate_on_submit():
        print(list(form))
        print(form.text.data)

    return render_template('simple_example.html', form=form)

# Authentication Stuff
# ===================================================================
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.password = form.password.data
        db.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)

@app.route('/forgot-password', methods=['GET', 'POST'])
def resetPassword():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.get_reset_password_token()
            send_password_reset_email(app.config, user.email, user.name, token)
        flash('Check your email for the instructions to reset your password')
        return redirect(url_for('login'))
    return render_template('forgot_password.html',
                           title='Reset Password', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if (user):
            print("User Found: ", user.name)
        if user is None or not user.check_password(form.password.data):
            print("Invalid password")
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)

    return render_template('login.html', title='Sign In', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login')) 


# Admin Section
# ===================================================================
class UserAdminView(ModelView):
    create_modal = True
    edit_modal = True
    can_export = True

    form_columns = ('name', 'email', "password", "roles")
    column_exclude_list = ["password_hash"]
    column_searchable_list = ['name', 'email', "roles"]
    column_filters = ['name', 'email', "roles"]

    def is_accessible(self):
        return "admin" in current_user.roles.lower()

    def inaccessible_callback(self, name, **kwargs):
        flash("You need to be an admin to view this page.")
        return redirect(url_for('index'))

admin.add_view(UserAdminView(User, db.session))


# Run Development Server
# ===================================================================
if __name__ == "__main__":
    app.run(host='0.0.0.0', debug = True)