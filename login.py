import mail
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
import MySQLdb.cursors
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm, RecaptchaField
from oauthlib.common import generate_token
from flask_mail import Mail, Message
from cryptography.fernet import Fernet
from twilio.rest import Client
import os
import pathlib
import secrets
import string
import requests
import datetime
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
app.config['MYSQL_PASSWORD'] = 'sql123lqs321'
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

account_sid ="ACb15c4415fb798a5d19fb503d195bf464" #'ACed3d1d976f65332ac83158ba83572744' #"ACb15c4415fb798a5d19fb503d195bf464"
auth_token = "5a985c5566c5e42184022c809b460612"#'105e3c1bad45b786c33fd75d3370f7aa' #"980e04b734f181d9664f63fb0b6b1130"
verify_sid = "VA46c7644a74f4c8feb0daecb15efb375f"
client = Client(account_sid, auth_token)

def convert_to_e164(raw_phone):
    """Convert a raw phone number to E.164 format."""
    if not raw_phone:
        return
    # Remove all non-numeric characters
    phone_numeric = ''.join(filter(str.isdigit, raw_phone))
    # Add country code for Singapore ('+65') in this case
    return phone_numeric
@app.route('/send', methods=['GET', 'POST'])
def send():
    if request.method == 'POST':
        phone_number = request.form['phone_number']
        session['phone_number'] = phone_number
        verification = client.verify.v2.services(verify_sid) \
          .verifications \
          .create(to=phone_number, channel="sms")
        return redirect(url_for('verify'))
    return render_template('send.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        otp_code = request.form['otp_code']

        verification_check = client.verify.v2.services(verify_sid) \
          .verification_checks \
          .create(to=session['phone_number'], code=otp_code)

        if verification_check.status == 'approved':
            flash('OTP Verified Successfully!', 'success')
            user_id = session['phone_number']
            event_type = 'PhoneLogin'
            details = 'Successful OTP login'
            log_audit_event(event_type, user_id, details)
            return render_template('home.html', username=session['phone_number'])
        else:
            flash('Invalid OTP!', 'danger')
            user_id = session['phone_number']
            event_type = 'PhoneLogin'
            details = 'Failed OTP login'
            log_audit_event(event_type, user_id, details)

    return render_template('verify.html')

@app.route('/success')
def success():
    return "OTP Verification Successful!"
@app.route("/actlog", methods=['GET','POST'])
def actlog():
    if request.method == 'POST' and 'password' in request.form:
        admin = request.form['password']
        if admin == 'admin':
            try:
                            ##create table in sql called audit
            #'''
            # audit_id  PK, NN, AI      INT
            # timestamp NN              DATETIME
            # user_id   NN
            # event_type NN
            # details   NN
            # '''
                cursor = mysql.connection.cursor()
                #cursor.execute('DELETE FROM audit')
                #mysql.connection.commit()
                cursor.execute('SELECT * FROM audit')
                audit = cursor.fetchall()
                audit_data = '\n'.join(str(row) for row in audit)  # Convert each row to a string
                return render_template('admin.html', audit_data=audit_data)
            except Exception as e:
                print("Error fetching audit log:", str(e))
    return render_template('actlog.html')
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        cursor = mysql.connection.cursor()
        cursor.execute('DELETE FROM audit')
        mysql.connection.commit()
        cursor.execute('SELECT * FROM audit')
        audit = cursor.fetchall()
        audit_data = '\n'.join(str(row) for row in audit)
        return render_template('admin.html', audit_data=audit_data)
def log_audit_event(event_type, user_id, details):
    try:
        cursor = mysql.connection.cursor()
        timestamp = datetime.datetime.now()
        cursor.execute(
            "INSERT INTO audit VALUES (Null, %s, %s, %s, %s)",
            (timestamp, user_id, event_type, details)
        )
        mysql.connection.commit()
    except Exception as e:
        print("Error logging audit event:", str(e))

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
    try:
        if "google_id" in session:
            user_id = session['name']
            event_type = 'GoogleLogin'
            details = 'Successful login'
            log_audit_event(event_type, user_id, details)
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

            if account and bcrypt.check_password_hash(user_hashpwd, password) and formL.validate_on_submit():
                curuse = request.form['username']
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                print(curuse)
                cursor.execute('SET SQL_SAFE_UPDATES = 0')
                cursor.execute('UPDATE accounts SET attempts = 0 WHERE username = %s', (curuse,))
                mysql.connection.commit()
                account = cursor.fetchone()
                print(account)
                user_id = session['username']
                event_type = 'Login'
                details = 'Successful login'
                log_audit_event(event_type, user_id, details)
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
                    user_id = session['username']
                    event_type = 'Login'
                    details = 'Account locked'
                    log_audit_event(event_type, user_id, details)
                    msg = 'Account locked!'
                else:
                    user_id = session['username']
                    event_type = 'Login'
                    details = 'Incorrect password'
                    log_audit_event(event_type, user_id, details)
                    msg = 'Incorrect username/password!'
    except Exception:
        user_id = request.remote_addr
        event_type = 'Login'
        details = 'Invalid username'
        log_audit_event(event_type, user_id, details)
        msg = 'Username does not exist'
    return render_template('index.html', msg=msg, form=formL)


@app.route("/goo")
def goo():
    if "google_id" in session:
        user_id = session['name']
        event_type = 'GoogleLogin'
        details = 'Successful login'
        log_audit_event(event_type, user_id, details)
        return redirect(url_for("home"))  # Redirect to home page if already logged in

    # If not logged in, initiate Google OAuth 2.0 login process
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)
@app.route('/logout')
def logout():
    if 'username' in session:
        user_id = session['username']
        event_type = 'Logout'
        details = 'Successful logout'
        log_audit_event(event_type, user_id, details)
    elif 'google_id' in session:
        user_id = session['name']
        event_type = 'GoogleLogout'
        details = 'Successful logout'
        log_audit_event(event_type, user_id, details)
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
    user_id = session['name']
    event_type = 'GoogleLogin'
    details = 'Successful login'
    log_audit_event(event_type, user_id, details)
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
            user_id = username
            event_type = 'Register'
            details = 'Successful registration'
            log_audit_event(event_type, user_id, details)
            cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s, %s, %s, NULL)',
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
    elif 'phone_number' in session:
        return render_template('home.html', username=session['phone_number'])
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
        return render_template('profile.html', account=session['name'], email=session['name']+'@gmail.com')
    elif 'phone_number' in session:
        return render_template('profile.html', account=session['phone_number'])
    else:
        return redirect(url_for('login'))
@app.route('/tetris')
def tetris():
    if 'loggedin' in session:
        return render_template('tetris.html')
    elif 'google_id' in session:
        return render_template('tetris.html')
    elif 'phone_number' in session:
        return render_template('tetris.html')
    else:
        return redirect(url_for('login'))
@app.route('/vone')
def vone():
    return render_template('vone.html')
@app.route('/vtwo')
def vtwo():
    return render_template('vtwo.html')
@app.route('/vtre')
def vtre():
    return render_template('vtre.html')
@app.route('/vfor')
def vfor():
    return render_template('vfor.html')
@app.route('/vdg', methods=['GET', 'POST'])
def vdg():
    if request.method == 'POST' and 'password' in request.form:
        pin = request.form['password']
        if pin == '8888':
            user_id = session.get('name')
            event_type = 'Video restrict, Google'
            details = 'Successful video unrestriction'
            log_audit_event(event_type, user_id, details)
            user_id = session.get('username')
            event_type = 'Video restrict'
            details = 'Successful video unrestriction'
            log_audit_event(event_type, user_id, details)
            user_id = session.get('phone_number')
            event_type = 'Video restrict, Phone'
            details = 'Successful video unrestriction'
            log_audit_event(event_type, user_id, details)
            return render_template('vfor.html')
        else:
            user_id = session.get('name')
            event_type = 'Video restrict, Google'
            details = 'Failed video unrestriction'
            log_audit_event(event_type, user_id, details)
            user_id = session.get('username')
            event_type = 'Video restrict'
            details = 'Failed video unrestriction'
            log_audit_event(event_type, user_id, details)
            user_id = session.get('phone_number')
            event_type = 'Video restrict, Phone'
            details = 'Failed video unrestriction'
            log_audit_event(event_type, user_id, details)
            msg = 'Invalid PIN'
            return render_template('vdg.html', msg=msg)
    return render_template('vdg.html')
@app.route('/vfai')
def vfai():
    return render_template('vfai.html')
@app.route('/vjy')
def vjy():
    return render_template('vjy.html')
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
        user_id = email
        event_type = 'Forget'
        details = 'Successful email confirmation'
        log_audit_event(event_type, user_id, details)
    except Exception as e:
        user_id = email
        event_type = 'Forget'
        details = 'Failed email confirmation'
        log_audit_event(event_type, user_id, details)
        print(f"Error sending email: {e}")
    pass


@app.route('/forget', methods=['GET', 'POST'])
def forget():
    msg = ''
    if request.method == 'POST':
        input_email = request.form.get('email')
        user_id = input_email
        event_type = 'Forget'
        details = 'Forget password'
        log_audit_event(event_type, user_id, details)
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
                user_id = input_email
                event_type = 'Forget'
                details = 'Successful email sent'
                log_audit_event(event_type, user_id, details)
                msg = 'Email sent successfully! Check your email inbox'
                break
        else:
            user_id = input_email
            event_type = 'Forget'
            details = 'Failed email sent'
            log_audit_event(event_type, user_id, details)
            msg = "Email not found!"

    return render_template('forget.html', msg=msg)
@app.route('/reset/<reset_token>', methods=['GET', 'POST'])
def reset(reset_token):
    msg = ''

    print(reset_token)
    if request.method == 'POST' and 'npassword' in request.form and 'cpassword' in request.form:
        new_password = request.form['npassword']
        confirm_password = request.form['cpassword']

        if new_password != confirm_password:
            msg = 'Passwords do not match.'
            return render_template('reset.html', msg=msg, reset_token=reset_token)

        hashpwd = bcrypt.generate_password_hash(new_password).decode('utf-8')  # Ensure it's a string
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT email FROM accounts WHERE resettoken = %s', (reset_token,))
        account = cursor.fetchone()
        user_id = reset_token
        event_type = 'Reset'
        details = 'Reset password'
        log_audit_event(event_type, user_id, details)
        if not account:
            user_id = reset_token
            event_type = 'Reset'
            details = 'Invalid token'
            log_audit_event(event_type, user_id, details)
            msg = "Invalid or expired reset token."
            return render_template('reset.html', msg=msg, reset_token=reset_token)
        email = account['email']
        cursor.execute('SET SQL_SAFE_UPDATES = 0')
        cursor.execute('UPDATE accounts SET password = %s, resettoken = NULL WHERE resettoken = %s',(hashpwd, reset_token))
        mysql.connection.commit()
        user_id = reset_token
        event_type = 'Reset'
        details = 'Successful password reset'
        log_audit_event(event_type, user_id, details)
        # For demonstration purposes
        print("New Password:", new_password)
        cursor.execute('SELECT password FROM accounts WHERE email = %s', (email,))
        account = cursor.fetchone()
        affected_rows = cursor.rowcount
        print(f"Rows affected after password update: {affected_rows}")
        # Print the hashed password
        password = account['password']
        print("Current Hashed Password:", str(password))

        if cursor.rowcount == 0:
            user_id = reset_token
            event_type = 'Reset'
            details = 'Failed password reset'
            log_audit_event(event_type, user_id, details)
            msg = 'Error updating password or token not found.'
        else:
            msg = 'Password has been successfully reset. You can now log in with your new password.'
            mysql.connection.commit()

    return render_template('reset.html', msg=msg, reset_token=reset_token)

if __name__== '__main__':
    app.run(port=80,debug=True)
