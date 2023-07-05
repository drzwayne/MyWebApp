from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
import MySQLdb.cursors
from flask_bcrypt import Bcrypt
import re
import cryptography
from cryptography.fernet import Fernet

app = Flask(__name__)
bcrypt = Bcrypt(app)
# Change this to your secret key (can be anything, it's for extra protection)
app.secret_key = 'your secret key'
# Enter your database connection details below
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'sql123lqs321'
app.config['MYSQL_DB'] = 'pythonlogin'
app.config['MYSQL_PORT'] = 3306
# Intialize MySQL
mysql = MySQL(app)
# http://localhost:5000/MyWebApp/ - this will be the login page, we need to use both GET and POST #requests
@app.route('/', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()
        user_hashpwd = account['password']
        #user_hashpwd = bcrypt.generate_password_hash(password)
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
            return render_template('home.html', username=username, email=decrypted_email.decode())
    else:
        msg = 'Incorrect username/password!'
    return render_template('index.html', msg='')
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
        #key = Fernet.generate_key()
        #with open("symmetric.key","wb") as fo:
        #    fo.write(key)
        #f = Fernet(key)
        #encrypted_email = f.encrypt(email)
        email_key = Fernet.generate_key()
        email_fernet = Fernet(email_key)
        encrypted_email = email_fernet.encrypt(email)
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s, %s)', (username, hashpwd, encrypted_email, email_key))
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
if __name__== '__main__':
    app.run()
