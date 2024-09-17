from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
import MySQLdb.cursors
import MySQLdb.cursors, re, hashlib

#https://codeshack.io/login-system-python-flask-mysql/#creatingthedatabaseandsettinguptables

app = Flask(__name__)

# Change this to your secret key (it can be anything, it's for extra protection)
app.secret_key = 'your secret key'

# Enter your database connection details below

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '1234'
app.config['MYSQL_DB'] = 'pythonlogin'

# Intialize MySQL
mysql = MySQL(app)

#---------------------------------------------------------------------------------------------

@app.route('/pythonlogin/', methods=['GET', 'POST'])
def login():
    # Output a message if something goes wrong...
    msg = ''
    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        # Retrieve the hashed password
        hash = password + app.secret_key
        hash = hashlib.sha1(hash.encode())
        password = hash.hexdigest()
        # Check if account exists using MySQL
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s AND password = %s', (username, password,))
        # Fetch one record and return the result
        account = cursor.fetchone()

        # If account exists in accounts table in out database
        if account:
            # Create session data, we can access this data in other routes
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            # Redirect to home page
            print(session['id'])
            return redirect(url_for('home'))
        else:
            # Account doesnt exist or username/password incorrect
            msg = 'Incorrect username/password!'
    # Show the login form with message (if any)
    return render_template('index.html', msg=msg)

#---------------------------------------------------------------------------------------------

@app.route('/pythonlogin/logout')
def logout():
    # Remove session data, this will log the user out
   session.pop('loggedin', None)
   session.pop('id', None)
   session.pop('username', None)
   # Redirect to login page
   return redirect(url_for('login'))


#---------------------------------------------------------------------------------------------

@app.route('/pythonlogin/register', methods=['GET', 'POST'])
def register():
    # Output message if something goes wrong...
    msg = ''
    # Check if "username", "password" and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

         # Check if account exists using MySQL
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()
        # If account exists show error and validation checks
        if account:
            msg = 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers!'
        elif not username or not password or not email:
            msg = 'Please fill out the form!'
        else:
            # Hash the password
            hash = password + app.secret_key
            hash = hashlib.sha1(hash.encode())
            password = hash.hexdigest()
            # Account doesn't exist, and the form data is valid, so insert the new account into the accounts table
            cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s)', (username, password, email,))
            mysql.connection.commit()
            msg = 'You have successfully registered!'

    elif request.method == 'POST':
        # Form is empty... (no POST data)
        msg = 'Please fill out the form!'
    # Show registration form with message (if any)
    return render_template('register.html', msg=msg)

#-------------------------------------------------------------------------------------------------------

# http://localhost:5000/pythonlogin/home - this will be the home page, only accessible for logged in users
@app.route('/')
def home():
    # Check if the user is logged in
    if 'loggedin' in session:
        # User is logged in, show them the home page
        user_id = session['id']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # Get aggregated training data from the sessions table
        cursor.execute('SELECT COUNT(*) AS training_sessions, '
                       'SUM(sparring_matches) AS sparring_matches, '
                       'SUM(injuries) AS injuries, '
                       'SUM(taps) AS taps '
                       'FROM sessions WHERE user_id = %s', (user_id,))
        training_data = cursor.fetchone()

        return render_template('home.html', username=session['username'], training_data=training_data)
    # User is not logged in, redirect to login page
    return redirect(url_for('login'))


#-------------------------------------------------------------------------------------------------------

# http://localhost:5000/pythinlogin/profile - this will be the profile page, only accessible for logged in users
@app.route('/pythonlogin/profile')
def profile():
    # Check if the user is logged in
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    # We need all the account info for the user so we can display it on the profile page
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
    account = cursor.fetchone()
    # Show the profile page with account info
    return render_template('profile.html', account=account)

#-------------------------------------------------------------------------------------------------------

@app.route('/add_session', methods=['GET', 'POST'])
def add_session():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        # Retrieve form data
        session_date = request.form['date']
        sparring_matches = int(request.form['sparring_matches'])
        injuries = request.form.get('injuries', '')
        taps = int(request.form['taps'])
        user_id = session['id']

        # Create a new session entry
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('INSERT INTO sessions (user_id, date, sparring_matches, injuries, taps) VALUES (%s, %s, %s, %s, %s)', 
                       (user_id, session_date, sparring_matches, injuries, taps))
        mysql.connection.commit()
        cursor.close()

        flash('Session added successfully!', 'success')
        return redirect(url_for('home'))

    return render_template('add_session.html')


#-------------------------------------------------------------------------------------------------------


@app.route('/add_technique', methods=['GET', 'POST'])
def add_technique():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Retrieve form data
        name = request.form['name']
        description = request.form['description']
        user_id = session['id']

        # Create a new session entry
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('INSERT INTO techniques (user_id, name, description) VALUES (%s, %s, %s)', 
                       (user_id, name, description))
        mysql.connection.commit()
        cursor.close()

        flash('Technique added successfully!', 'success')
        return redirect(url_for('home'))

    return render_template('add_technique.html')

#-------------------------------------------------------------------------------------------------------

@app.route('/techniques')
def list_techniques():
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM techniques WHERE user_id = %s', (session['id'],))
    techniques = cursor.fetchall()
    cursor.close()

    return render_template('techniques.html', techniques=techniques)


#-------------------------------------------------------------------------------------------------------


@app.route('/delete_technique/<int:technique_id>', methods=['POST'])
def delete_technique(technique_id):
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    # Ensure the technique belongs to the current user before deleting
    cursor.execute('DELETE FROM techniques WHERE id = %s AND user_id = %s', (technique_id, session['id']))
    mysql.connection.commit()
    cursor.close()

    flash('Technique deleted successfully!', 'success')
    return redirect(url_for('list_techniques'))

#-------------------------------------------------------------------------------------------------------


@app.route('/sesssions')
def list_sessions():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM sessions WHERE user_id = %s', (session['id'],))
    sessions = cursor.fetchall()
    cursor.close()

    return render_template('sessions.html', sessions = sessions)

#-------------------------------------------------------------------------------------------------------

@app.route('/delete_session/<int:session_id>', methods=['POST'])
def delete_session(session_id):
    # Check if the user is logged in
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    # Get the user's ID
    user_id = session['id']

    # Delete the session where the session_id matches and it belongs to the logged-in user
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('DELETE FROM sessions WHERE id = %s AND user_id = %s', (session_id, user_id))
    mysql.connection.commit()
    cursor.close()

    flash('Session deleted successfully!', 'success')
    return redirect(url_for('home'))

    
