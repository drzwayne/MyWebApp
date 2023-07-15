from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
import MySQLdb.cursors
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired, Length, AnyOf
import re
import cryptography
import attempt
from cryptography.fernet import Fernet
import os
import pathlib

import requests
from flask import Flask, session, abort, redirect, request
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests

app = Flask("Google Login App")
bcrypt = Bcrypt(app)
app.secret_key = "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" # make sure this matches with that's in client_secret.json
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'sql123lqs321'
app.config['MYSQL_DB'] = 'pythonlogin'
app.config['MYSQL_PORT'] = 3306
mysql = MySQL(app)
app.config['SECRET_KEY'] = 'Thisisasecret!'
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LciR-0mAAAAAEukfwSdVCfdo4CJOQ2H6PxeOQ4f' #remove mine and insert yours
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LciR-0mAAAAAPXpIIsU8WgGK7lgVHW_Vt-WcXyM'  #do the same^^^
class LoginForm(FlaskForm):
    recaptcha = RecaptchaField()

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1" # to allow Http traffic for local dev

GOOGLE_CLIENT_ID = "997230487603-rkve4vba3qvg3pjlmsuujbcpcsjnoeii.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://localhost/callback"
)
def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()

    return wrapper
global tries
tries = 0
@app.route('/', methods=['GET', 'POST'])
def login():
    msg = ''
    formL = LoginForm()
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()
        user_hashpwd = account['password']
        if account and bcrypt.check_password_hash(user_hashpwd, password):
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']

            email_key = account['emailkey']
            encrypted_email = account['email'].encode()
            f = Fernet(email_key)
            decrypted_email = f.decrypt(encrypted_email)
            return render_template('home.html', form=formL, username=username, email=decrypted_email.decode())
        else:
            def trial():
                global tries
                tries += 1
                print(tries)
                if tries > 2:
                    msg = 'Account locked'
                else:
                    msg = 'Incorrect password/username'
                return render_template('index.html', msg=msg, form=formL)
            trial()
    return render_template('index.html', msg=msg, form=formL)
@app.route("/goo")
def goo():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)
@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    session.clear()
    return redirect(url_for('login'))
@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    #if not session["state"] == request.args["state"]:
    #    abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    return render_template('home.html', username=session["name"])
@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        email = email.encode()
        hashpwd = bcrypt.generate_password_hash(password)
        email_key = Fernet.generate_key()
        email_fernet = Fernet(email_key)
        encrypted_email = email_fernet.encrypt(email)
        attempts = 0
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s, %s, %s)', (username, hashpwd, encrypted_email, email_key, attempts,))
        mysql.connection.commit()
        msg = 'You have successfully registered!'
    elif request.method == 'POST':
        msg = 'Please fill out the form!'
    return render_template('register.html', msg=msg)
@app.route('/home')
def home():
    if 'loggedin' in session:
        return render_template('home.html', username=session['username'])
    return redirect(url_for('login'))
@app.route('/profile')
def profile():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        account = cursor.fetchone()
        return render_template('profile.html', account=account)
    return redirect(url_for('login'))
@app.route('/tetris')
def tetris():
    if 'loggedin' in session:
        return render_template('tetris.html')
    return redirect(url_for('login'))
@app.route('/vone')
def vone():
    return render_template('vone.html')

if __name__== '__main__':
    app.run(host='127.0.0.1', port=80,debug=True)
