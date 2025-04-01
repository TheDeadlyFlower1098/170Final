
from flask import Flask, render_template, request, redirect, url_for
from sqlalchemy import create_engine, text
import hashlib

app = Flask(__name__)

con_str = "mysql://root:cset155@localhost/bank"
engine = create_engine(con_str, echo=True)
conn = engine.connect()

@app.route('/signup', methods=['GET'])
def signup_page():
    return render_template('signup.html')

@app.route('/signup', methods=['POST'])
def create_user():
    try:
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        username = request.form['username']
        ssn = request.form['ssn']
        address = request.form['address']
        phone_number = request.form['phone_number']
        password = request.form['password_hash']  # Fixed typo here

        if not first_name or not last_name or not username or not password or not ssn or not address or not phone_number:
            return render_template('signup.html', error="All fields are required", success=None)

        # Hash the password before saving it to the database (for security)
        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

        # Prepare the SQL query
        conn.execute(
            text('INSERT INTO users (first_name, last_name, password_hash, username, address, phone_number, ssn) '
                 'VALUES (:first_name, :last_name, :password_hash, :username, :address, :phone_number, :ssn)'),
            {'first_name': first_name, 'last_name': last_name, 'password_hash': hashed_password, 'username': username,
             'address': address, 'phone_number': phone_number, 'ssn': ssn}
        )
        conn.commit()

        return render_template('signup.html', error=None, success='Signup successful')

    except Exception as e:
        print(f"Error occurred during signup: {e}")
        return render_template('signup.html', error=f"Signup failed: {e}", success=None)

@app.route('/login', methods=['GET'])
def login_page():
     return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_user():
    try:
        username = request.form['username']
        password = request.form['password_hash']

        print(f"Received username: '{username}'")
        print(f"Received password: '{password}'")

        # Fetch the user from the database
        result = conn.execute(
            text('SELECT password_hash FROM users WHERE username = :username'),
            {'username': username}
        ).fetchone()

        if result:
            stored_password_hash = result[0]  # Assuming password_hash is the first column in the result
            print(f"Stored password hash: '{stored_password_hash}'")

            # Hash the entered password and compare with the stored hash
            hashed_input_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

            if stored_password_hash == hashed_input_password:
                print("Login successful")
                return render_template('home.html')
            else:
                print("Password mismatch")
                return render_template('login.html', error="Invalid password", success=None)
        else:
            print("User not found")
            return render_template('login.html', error="User not found", success=None)

    except Exception as e:
        print(f"Error occurred during login: {e}")
        return render_template('login.html', error="Login failed. Please try again.", success=None)

@app.route('/')
def home():
    return render_template('home.html')
@app.route('/admin_login', methods=['GET'])
def admin_login_page():
    return render_template('admin_login.html')

@app.route('/admin_login', methods=['POST'])
def admin_login():
    try:
        # Get the username and password from the form
        username = request.form['username']
        password = request.form['password_hash']  # Password entered by the user (plaintext)

        # Query the database to find the admin with the provided username
        result = conn.execute(
            text('SELECT * FROM admin WHERE username = :username'),
            {'username': username}
        ).fetchone()

        if result:
            stored_password = result['password_hash']  # Get the stored password (plaintext)

            # Check if the provided password matches the stored password
            if stored_password == password:
                return redirect(url_for('admin_dashboard'))  # Redirect to admin dashboard on success
            else:
                return render_template('admin_login.html', error="Invalid password", success=None)
        else:
            return render_template('admin_login.html', error="Admin not found", success=None)

    except Exception as e:
        print(f"Error during login: {e}")
        return render_template('admin_login.html', error="Login failed. Please try again.", success=None)


if __name__ == '__main__':
    app.run(debug=True)
