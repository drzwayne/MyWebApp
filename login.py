import MySQLdb.cursors
from cryptography.fernet import Fernet
from flask import Flask, render_template, redirect, url_for, session
from flask_bcrypt import Bcrypt
from flask_mysqldb import MySQL
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = 'your secret key'
app.config['RECAPTCHA_PUBLIC_KEY'] = 'your_reCAPTCHA_public_key'
app.config['RECAPTCHA_PRIVATE_KEY'] = 'your_reCAPTCHA_private_key'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'mysql'
app.config['MYSQL_DB'] = 'dbms_orders'
app.config['MYSQL_PORT'] = 3306

mysql = MySQL(app)


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    submit = SubmitField('Register')


@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = str(form.username.data)
        password = str(form.password.data)

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()

        if account and bcrypt.check_password_hash(account['hashpwd'], password):
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            email_key = account['emailkey']
            encrypted_email = account['email'].encode()
            f = Fernet(email_key)
            decrypted_email = f.decrypt(encrypted_email)
            return render_template('home.html', username=username, email=decrypted_email.decode())
        return 'Invalid username or password'

    return render_template('index.html', form=form, msg="" )


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


if __name__ == '__main__':
    app.run(debug=True)
