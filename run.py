from flask import Flask, render_template, request, redirect, url_for, flash, session

from flask_login import login_user, logout_user

from all_db import Session, Users
from flask_login import LoginManager

import secrets

app = Flask(__name__)

FILES_PATH = 'static/menu'

app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024
app.config['MAX_FORM_MEMORY_SIZE'] = 1024 * 1024 
app.config['MAX_FORM_PARTS'] = 255

app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

app.config['SECRET_KEY'] = secrets.token_urlsafe(16)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    with Session() as session:
        user = session.query(Users).filter_by(id = user_id).first()
        if user:
            return user

@app.after_request
def apply_csp(response):
    nonce = secrets.token_urlsafe(16)
    csp = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self'; "
        f"frame-ancestors 'none'; "
        f"base-uri 'self'; "
        f"form-action 'self'"
    )
    response.headers["Content-Security-Policy"] = csp
    response.set_cookie('nonce', nonce)
    return response

@app.route('/')
@app.route('/home')
def home():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)

    return render_template('home.html')

@app.route('/menu')
def menu():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)

    return render_template('menu.html', csrf_token=session["csrf_token"])

@app.route("/register", methods = ['GET','POST'])
def register():
    if request.method == 'POST':
        if request.form.get("csrf_token") != session["csrf_token"]:
            return "Запит заблоковано!", 403
        nickname = request.form['nickname']
        email = request.form['email']
        password = request.form['password']

        with Session() as cursor:
            if cursor.query(Users).filter_by(email=email).first() or cursor.query(Users).filter_by(nickname = nickname).first():
                flash('Acount with same email or user_name is alredy created', 'danger')
                return render_template('register.html',csrf_token=session["csrf_token"])

            new_user = Users(nickname=nickname, email=email)
            new_user.set_password(password)
            cursor.add(new_user)
            cursor.commit()
            cursor.refresh(new_user)
            login_user(new_user)
            return redirect(url_for('home'))
    return render_template('register.html',csrf_token=session["csrf_token"])

@app.route("/login", methods = ["GET","POST"])
def login():
    if request.method == 'POST':
        nickname = request.form['nickname']
        password = request.form['password']

        with Session() as cursor:
            user = cursor.query(Users).filter_by(nickname = nickname).first()
            if user and user.check_password(password):
                login_user(user)
                return redirect(url_for('home'))

            flash('Wrong pasword', 'danger')

    return render_template('login.html', csrf_token=session["csrf_token"])

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)