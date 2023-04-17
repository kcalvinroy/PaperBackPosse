# Libraries imported
import os
import re
import urllib
import hashlib
import datetime
import requests
import urllib.request
from fileinput import filename
from datetime import timedelta
import mysql.connector as database
from flask_login import current_user
from pinata_python.pinning import Pinning
from werkzeug.utils import secure_filename
from flask import Flask,render_template, redirect, request, url_for, session, send_file, g


app = Flask(__name__)
app.secret_key = '12345678'
salt = "5gz69"


connection = database.connect(user = 'e5q9hxt4ztfq9gj4', password = 'x3u5kccywg1ovn1v', host='q0h7yf5pynynaq54.cbetxkdyhwsb.us-east-1.rds.amazonaws.com', database = 'j2c0nme0hohrxwwk')
cursor = connection.cursor()

@app.route("/", methods=['GET'])
def index():
    
    return render_template("index.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Message incase something goes wrong
    msg = ''
    # Checks on password and user name
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        #variables for easy access
        username = request.form['username']
        password = request.form['password']
        password=password+salt
        h = hashlib.md5(password.encode())
        password=str(h.hexdigest())
        cursor.execute('SELECT * FROM user WHERE username = %s AND password = %s', (username, password))
        # Fetch record and return result
        account = cursor.fetchone()
        # return hh.hexdigest()
        # if account exists
        if account:
            # CREATE session data, accessible in other routes
            session.clear()
            session['loggedin'] = True
            session['userID']=account[0]
            session['username']=account[1]
            session['email']=account[2]
            #redirect to homepage
            return redirect(url_for('books'))
        else:
            # Account not in existance or incorect logins
            msg = 'Incorrect username/password!'
    return render_template('login.html', msg=msg)

@app.route('/logout')
def logout():
    # Remove session data, logging out the user
    session.pop('loggedin', None)
    session.pop('UserID', None)
    session.pop('username', None)
    #Redirect to login page
    return redirect(url_for('login'))

@app.route("/register", methods=['GET', 'POST'])
def register():
    
    # Message incase something goes wrong
    msg = ''
    # Message incase of success
    mes = ''
    if request.method == 'POST' and 'firstname' in request.form and 'surname' in request.form and 'username' in request.form and 'email' in request.form and 'password' in request.form:
        #variables for easy access
        try:
            surname = str(request.form['surname'])
            firstname = str(request.form['firstname'])
            username = str(request.form['username'])
            email = str(request.form['email'])
            password = (request.form['password'])
            # check if account exists
            cursor.execute('SELECT * FROM user WHERE username = %s', (username,))
            account = cursor.fetchone()
            # If account exists show error and validation checks
            if account:
                msg = 'Account already exits!'
            elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                msg='Invalid email address!'
            elif not re.match(r'[A-Za-z0-9]+', username):
                msg = 'Username must only contain characters and numbers!'
            elif not surname or not firstname or not username or not password or not email:
                msg = 'Please fill out the form!'
            else:
                password=password+salt
                h = hashlib.md5(password.encode())
                password=str(h.hexdigest())
                #Account doesnt exist and form data is valid, now insert new account into accounts table
                cursor.execute('INSERT INTO user(surname, firstname, username, email, password) VALUES(%s, %s, %s, %s, %s)', (surname, firstname, username, email, password,))
                connection.commit()
                mes = 'Successfully registered!'
        except database.Error as e:
            msg='Error Creating c: {e}' 
    elif request.method == 'POST':
                # Form is empty
                msg = 'Please fill in the form'
    
    return render_template("register.html", mes=mes, msg=msg)

@app.route("/addBook", methods=['GET', 'POST'])
def addBook():
    # Message incase something goes wrong
    msg = ''
    # Message incase of success
    mes = ''
    if 'loggedin' in session:
        userID = str(session['userID'])
        if request.method == 'POST' and 'title' in request.form and 'author' in request.form and 'category' in request.form and 'descr' in request.form and 'avail' in request.form:
            #variables for easy access
            try:
                title = str(request.form['title'])
                author = str(request.form['author'])
                category = str(request.form['category'])
                descr = str(request.form['descr'])
                avail = str(request.form['avail'])
                # check if book exists
                cursor.execute('SELECT * FROM book WHERE title = %s', (title,))
                book = cursor.fetchone()
                # If book exists show error and validation checks
                if book:
                    msg = 'Book title already exits!'
                elif not re.match(r'[A-Za-z0-9]+', author):
                    msg = 'Author must only contain characters and numbers!'
                elif not title or not author or not category or not descr or not avail:
                    msg = 'Please fill out the form!'
                else:
                    
                    #Book doesnt exist and form data is valid, now insert new book into book table
                    cursor.execute('INSERT INTO book(userID, title, author, category, descr, avail) VALUES(%s, %s, %s, %s, %s, %s)', (userID, title, author, category, descr, avail,))
                    connection.commit()
                    mes = 'Successfully added Title!'
            except database.Error as e:
                msg='Error Creating c: {e}' 
        elif request.method == 'POST':
                    # Form is empty
                    msg = 'Please fill in the form'
        
    return render_template("addBook.html", mes=mes, msg=msg)

@app.route("/books", methods=['GET', 'POST'])
def books():
    if 'loggedin' in session:
        # books
        cursor.execute('SELECT userID, title, author, category, descr, avail FROM book')
    else:
        return redirect(url_for('login'))
    return render_template("books.html", cursor=cursor)

@app.route("/mybooks", methods=['GET', 'POST'])
def mybooks():
    if 'loggedin' in session:
        # books
        cursor.execute('SELECT userID, title, author, category, descr, avail FROM book Where userID='+str(session['userID']))
    else:
        return redirect(url_for('login'))
    return render_template("books.html", cursor=cursor)

@app.route("/cat_<string:categorys>", methods=['GET', 'POST'])
def cat_(categorys):
    if 'loggedin' in session:
        categorys=str(categorys)
        # books
        cursor.execute('SELECT userID, title, author, category, descr, avail FROM book Where category=%s', (categorys,))
    else:
        return redirect(url_for('login'))
    return render_template("books.html", cursor=cursor)


if __name__ == '__main__':
    app.run(debug = True)
