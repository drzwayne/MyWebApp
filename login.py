from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
import MySQLdb.cursors
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm, RecaptchaField

from cryptography.fernet import Fernet
import os
import pathlib
import secrets
import string
import requests
from flask import Flask, session, abort, redirect, request
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
import uuid
import time

app = Flask("Google Login App")
bcrypt = Bcrypt(app)
app.secret_key = "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" # make sure this matches with that's in client_secret.json
app.config['MYSQL_HOST'] = '127.0.0.1'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'mysql'
app.config['MYSQL_DB'] = 'pythonlogin'
app.config['MYSQL_PORT'] = 3306
app.config['SECRET_KEY'] = 'Thisisasecret!'
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LciR-0mAAAAAEukfwSdVCfdo4CJOQ2H6PxeOQ4f' #remove mine and insert yours
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LciR-0mAAAAAPXpIIsU8WgGK7lgVHW_Vt-WcXyM'  #do the same^^^
mysql = MySQL(app)
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
tokens = {}
def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()

    return wrapper
@app.route('/', methods=['GET', 'POST'])
def login():
    msg = ''
    formL = LoginForm()

    # Check if user is already logged in via Google ID
    if "google_id" in session:
        return redirect(url_for("home"))

    elif request.method == 'POST':
        # Check if the login request is via email for "Magic Link"
        if 'email' in request.form:
            email = request.form['email']
            token = uuid.uuid4().hex
            tokens[token] = {"email": email, "expiry": time.time() + 600}  # 10 min expiry
            # Here, send email with link to '/auth/{token}' using an email service/library
            msg = "Magic link sent to your email!"

        # Otherwise, use the existing username/password logic
        elif 'username' in request.form and 'password' in request.form:
            # Your existing authentication logic starts here:
            username = request.form['username']
            password = request.form['password']
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
            account = cursor.fetchone()

            if account:
                user_hashpwd = account['password']
                session['id'] = account['id']
                session['username'] = account['username']

                if bcrypt.check_password_hash(user_hashpwd, password):
                    cursor.execute('SET SQL_SAFE_UPDATES = 0')
                    cursor.execute('UPDATE accounts SET attempts = 0 WHERE username = %s', (username,))
                    mysql.connection.commit()
                    session['loggedin'] = True
                    return render_template('home.html', form=formL, username=username)

                else:
                    cursor.execute('SET SQL_SAFE_UPDATES = 0')
                    cursor.execute('UPDATE accounts SET attempts = attempts + 1 WHERE username = %s', (username,))
                    cursor.execute('SELECT attempts FROM accounts WHERE username = %s AND attempts >2', (username,))
                    mysql.connection.commit()
                    account = cursor.fetchone()
                    if account:
                        msg = 'Account locked!'
                    else:
                        msg = 'Incorrect username/password!'

    return render_template('index.html', msg=msg, form=formL)
@app.route("/goo")
def goo():
    if "google_id" in session:
        return redirect(url_for("home"))  # Redirect to home page if already logged in

    # If not logged in, initiate Google OAuth 2.0 login process
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)
@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    #session.clear()
    session.pop('google_id', None)
    session.pop('name', None)
    session.pop('state', None)
    session.clear()
    return redirect(url_for('login'))
@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)
    # Check if the state matches to prevent CSRF attacks
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
    # Store user information in the session
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
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM accounts WHERE username = %s OR email = %s", (username, email,))
        existing_account = cursor.fetchone()

        if existing_account:
            # An account with the same username or email already exists
            msg = 'An account with the same username or email already exists!'
        else:
            # Create a new account
            email = email.encode()
            hashpwd = bcrypt.generate_password_hash(password)
            email_key = Fernet.generate_key()
            email_fernet = Fernet(email_key)
            encrypted_email = email_fernet.encrypt(email)
            attempts = 0

            cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s, %s, %s)',
                           (username, hashpwd, encrypted_email, email_key, attempts,))
            mysql.connection.commit()
            msg = 'You have successfully registered!'
    elif request.method == 'POST':
        msg = 'Please fill out the form!'
    return render_template('register.html', msg=msg)
@app.route('/home')
def home():
    if 'loggedin' in session:           #does not work
        print('home session')
        return render_template('home.html', username=session['username'])
    elif 'google_id' in session:
        return render_template('home.html', username=session['name'])
    return redirect(url_for('login'))
@app.route('/profile')
def profile():
    if 'loggedin' in session:
        print('profile session')
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        account = cursor.fetchone()
        email_key = account['emailkey']
        encrypted_email = account['email'].encode()
        f = Fernet(email_key)
        decrypted_email = f.decrypt(encrypted_email)
        return render_template('profile.html', account=account['username'], email=decrypted_email.decode())
    elif 'google_id' in session:
        print(session)
        return render_template('profile.html', account=session['name'])
@app.route('/tetris')
def tetris():
    if 'loggedin' in session:
        return render_template('tetris.html')
    elif 'google_id' in session:
        return render_template('tetris.html')
@app.route('/vone')
def vone():
    return render_template('vone.html')

def generate_reset_token(token_length=32):
    # Generate a cryptographically secure random token
    characters = string.ascii_letters + string.digits
    token = ''.join(secrets.choice(characters) for _ in range(token_length))
    return token
@app.route('/auth/<token>')
def authenticate(token):
    data = tokens.get(token)
    if not data:
        return "Invalid or expired link"
    if time.time() > data['expiry']:
        del tokens[token]
        return "Link expired"
    # Here, you'd typically create a session for the user and log them in
    return f"Welcome, {data['email']}!"

if __name__ == "__main__":
    app.run(debug=True)
@app.route('/forget', methods=['GET', 'POST'])
def forget():
    msg = ''
    if request.method == 'POST' and 'email' in request.form:
        nemail = request.form['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT emailkey, email FROM accounts")
        encrypted_email_data = cursor.fetchall()
        decrypted_emails = []
        for row in encrypted_email_data:
            email_key = row['emailkey']
            encrypted_email = row['email']
            f = Fernet(email_key)
            decrypted_email = f.decrypt(encrypted_email).decode('utf-8')
            decrypted_emails.append(decrypted_email)
        if nemail in decrypted_emails:
            reset_token = generate_reset_token()
            print("User's email found. Proceed with password reset.", reset_token)
            return render_template('reset.html', email=nemail, reset_token=reset_token)
            #return redirect(url_for('reset', email=nemail, reset_token=reset_token))
            #msg = 'An email with instructions for password recovery has been sent to your registered email address.'
        else:
            print("User's email not found. Cannot proceed with password reset.")
            msg = 'Email not found. Please enter your registered email address.'
    return render_template('forget.html', msg=msg)

@app.route('/reset', methods=['GET', 'POST'])
def reset(reset_token):
    msg = ''
    if request.method == 'POST' and 'email' in request.form and 'npassword' in request.form and 'cpassword' in request.form:
        email = request.form['email']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        print(email)
        if new_password == confirm_password:
            hashpwd = bcrypt.generate_password_hash(new_password)
            print("New Password:", new_password)
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SET SQL_SAFE_UPDATES = 0')
            cursor.execute('UPDATE accounts SET password = %s WHERE email = %s', (hashpwd,email))
            mysql.connection.commit()
            msg = 'Password has been successfully reset. You can now log in with your new password.'
        else:
            msg = 'Passwords do not match. Please make sure both passwords are the same.'
    return render_template('reset.html', msg=msg, reset_token=reset_token)
if __name__== '__main__':
    app.run(port=80,debug=True)
