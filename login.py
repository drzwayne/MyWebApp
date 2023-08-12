import mail
from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
import MySQLdb.cursors
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm, RecaptchaField
from oauthlib.common import generate_token
from flask_mail import Mail, Message
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

app.config['MAIL_SERVER'] = 'smtp.googlemail.com'  # for gmail
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'gitpain1@gmail.com'  # replace with your email
app.config['MAIL_PASSWORD'] = 'jbdxievndfsltdlk'
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
mail = Mail(app)
@app.route("/actlog", methods=['get','post'])
def actlog():
    if request.method == 'post' and 'pass' in request.form:
        if request.form['pass'] == 'ass':
            return render_template('viewactlog')



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
    if "google_id" in session:
        return redirect(url_for("home"))
    elif request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        print('c1')
        username = request.form['username']
        password = request.form['password']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()
        print(account)
        user_hashpwd = account['password']
        print(user_hashpwd)
        session['id'] = account['id']
        session['username'] = account['username']

        if account and bcrypt.check_password_hash(user_hashpwd, password):
            curuse = request.form['username']
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            print(curuse)
            cursor.execute('SET SQL_SAFE_UPDATES = 0')
            cursor.execute('UPDATE accounts SET attempts = 0 WHERE username = %s', (curuse,))
            mysql.connection.commit()
            account = cursor.fetchone()
            print(account)
            session['loggedin'] = True
            return render_template('home.html', form=formL, username=username)

        else:
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            curuse = request.form['username']
            print(curuse)
            cursor.execute('SET SQL_SAFE_UPDATES = 0')
            cursor.execute('UPDATE accounts SET attempts = attempts + 1 WHERE username = %s', (curuse,))
            cursor.execute('SELECT attempts FROM accounts WHERE username = %s AND attempts >2', (curuse,))
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


def send_recovery_email(email, token):
    try:

        reset_link = url_for('reset', reset_token=token, _external=True)

        # Create the email message
        msg = Message("Password Reset Request", sender="ass@gmail.com", recipients=[email])
        msg.body = f'''To reset your password, click the following link:
{reset_link}

If you did not make this request, please ignore this email.
'''

        # Send the email
        mail.send(msg)

    except Exception as e:
        print(f"Error sending email: {e}")
    pass


@app.route('/forget', methods=['GET', 'POST'])
def forget():
    msg = ''
    if request.method == 'POST':
        input_email = request.form.get('email')

        # Fetch the account with the inputted email
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM accounts")
        accounts = cursor.fetchall()

        # Iterate over accounts to check decrypted emails
        for account in accounts:
            email_key = account['emailkey']
            encrypted_email = account['email'].encode()
            f = Fernet(email_key)
            decrypted_email = f.decrypt(encrypted_email).decode()
            print(decrypted_email)
            # Compare decrypted email with the inputted email
            if decrypted_email == input_email:
                # Generate a token and send recovery email
                token = generate_token()  # Implement a function to generate a token
                send_recovery_email(decrypted_email, token)  # Implement the function to send an email
                cursor.execute('SET SQL_SAFE_UPDATES = 0')
                cursor.execute('UPDATE accounts SET resettoken = %s WHERE email = %s', (token, encrypted_email))
                mysql.connection.commit()  # Ensure that you commit your changes
                break
        else:
            msg = "Email not found!"

    return render_template('forget.html', msg=msg)
@app.route('/reset/<reset_token>', methods=['GET', 'POST'])
def reset(reset_token):
    msg = ''
    print("reset token:", reset_token)
    if request.method == 'POST' and 'npassword' in request.form and 'cpassword' in request.form:
        new_password = request.form['npassword']
        confirm_password = request.form['cpassword']

        if new_password != confirm_password:
            msg = 'Passwords do not match.'
            return render_template('reset.html', msg=msg, reset_token=reset_token)

        hashpwd = bcrypt.generate_password_hash(new_password).decode('utf-8')  # Ensure it's a string
        print("New Password:", new_password)
        print("hashed new password:", hashpwd)
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # Get the email or username associated with the reset token before updating it
        cursor.execute('SELECT email FROM accounts WHERE resettoken = %s', (reset_token,))
        account = cursor.fetchone()
        if not account:
            msg = "Invalid or expired reset token."
            return render_template('reset.html', msg=msg, reset_token=reset_token)
        email = account['email']

        # Update the user's password using the reset_token
        cursor.execute('SET SQL_SAFE_UPDATES = 0')
        cursor.execute('UPDATE accounts SET password = %s, resettoken = NULL WHERE resettoken = %s', (hashpwd, reset_token))
        mysql.connection.commit()

        # Now fetch the hashed password using the email
        cursor.execute('SELECT password FROM accounts WHERE email = %s', (email,))
        account = cursor.fetchone()

        # Print the hashed password
        password = account['password']
        print("Current Hashed Password:", str(password))



        if cursor.rowcount == 0:
            msg = 'Error updating password or token not found.'
        else:
            msg = 'Password has been successfully reset. You can now log in with your new password.'
            mysql.connection.commit()

    return render_template('reset.html', msg=msg, reset_token=reset_token)




if __name__== '__main__':
    app.run(port=80,debug=True)
