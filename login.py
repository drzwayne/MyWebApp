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

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = 'your secret key'
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
            ##decryption codes
            #encrypted_email = account['email'].encode()
            #file = open("symmetric.key","rb")
            #key = file.read()
            #file.close()
            #f = Fernet(key)
            #decrypted_email = f.decrypt(encrypted_email)
            #print(decrypted_email.decode())
            #ms = 'logged in successfully:' + decrypted_email.decode()##
            email_key = account['emailkey']
            encrypted_email = account['email'].encode()
            f = Fernet(email_key)
            decrypted_email = f.decrypt(encrypted_email)
            return render_template('home.html', form=formL, username=username, email=decrypted_email.decode())
        else:
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('UPDATE accounts SET attempts = 1 WHERE username = %s', (request.form['username'],))
            cursor.execute('SELECT attempts FROM accounts WHERE attempts = 3')
            account = cursor.fetchone()
            if account:
                msg = 'Account locked!'
            else:
                msg = 'Incorrect username/password!'
    return render_template('index.html', msg=msg, form=formL)
@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('login'))
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
        cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s, %s, %d)', (username, hashpwd, encrypted_email, email_key, attempts,))
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
    app.run(debug=True)
