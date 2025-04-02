from flask import Flask, render_template, request, redirect, url_for, flash, session
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
             'address': address, 'phone_number': phone_number, 'ssn': ssn, 'approved':'false'}
        )
        conn.commit()

        return render_template('signup.html', error=None, success='Signup successful wait for account to be approved')

    except Exception as e:
        print(f"Error occurred during signup: {e}")
        return render_template('signup.html', error=f"Signup failed: {e}", success=None)

@app.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_user():
    try:
        # Get username and password from form
        username = request.form['username']
        password = request.form['password_hash']  # The plain text password entered by the user

        # Print received credentials for debugging
        print(f"Received username: '{username}'")
        print(f"Received password: '{password}'")

        # Fetch the user from the database based on username
        result = conn.execute(
            text('SELECT password_hash, approved FROM users WHERE username = :username'),
            {'username': username}
        ).fetchone()

        if result:
            # Extract stored password hash and approval status from the result
            stored_password_hash = result[0]
            is_approved = result[1]
            print(f"Stored password hash: '{stored_password_hash}'")
            print(f"User approved: {is_approved}")

            # **Check if the user is approved**
            if not is_approved:
                print("User not approved")
                return render_template('login.html', error="Your account is not approved yet.", success=None)

            # **Only check password if the user is approved**
            # Hash the entered password using sha256 to match the stored hash
            hashed_input_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
            print(f"Hashed entered password: '{hashed_input_password}'")

            # Compare hashed password
            if stored_password_hash == hashed_input_password:
                print("Login successful")
                return render_template('home.html')  # Redirect to the home page or another page
            else:
                print("Password mismatch")
                return render_template('login.html', error="Invalid password", success=None)
        else:
            print("User not found")
            return render_template('login.html', error="User not found", success=None)

    except Exception as e:
        print(f"Error occurred during login: {e}")
        return render_template('login.html', error="Login failed. Please try again.", success=None)

    
@app.route('/admin_login', methods=['GET'])
def login_adminpage():
    return render_template('admin_login.html')

@app.route('/admin_login', methods=['POST'])
def login_admin():
    try:
        username = request.form['username']
        password = request.form['password_hash']

        print(f"Received username: '{username}'")
        print(f"Received password: '{password}'")

        result = conn.execute(
            text('SELECT username, password_hash FROM admin WHERE username = :username'),
            {'username': username}
        ).fetchone()

        if result:
            stored_username, stored_password = result
            print(f"Stored username: '{stored_username}'")
            print(f"Stored password: '{stored_password}'")

            if stored_password == password:
                print("Login successful")
                return render_template('home.html')
            else:
                print("Password mismatch")
                return render_template('admin_login.html', error="Invalid password", success=None)
        else:
            print("User not found")
            return render_template('admin_login.html', error="User not found", success=None)

    except Exception as e:
        print(f"Error occurred during login: {e}")
        return render_template('admin_login.html', error="Login failed. Please try again.", success=None)


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/add_money', methods=['GET', 'POST'])
def add_money():
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirect if not logged in

    if request.method == 'POST':
        user_id = session['user_id']
        card_number = request.form['card_number']
        expiry_date = request.form['expiry_date']
        ccv = request.form['ccv']
        amount = float(request.form['amount'])

        # Verify card details (simple validation for demonstration)
        if len(card_number) != 16 or not card_number.isdigit():
            flash('Invalid card number', 'danger')
            return redirect(url_for('add_money'))

        # Insert into card_transactions table
        insert_query = text("""
            INSERT INTO card_transactions (user_id, card_number, expiry_date, ccv, amount)
            VALUES (:user_id, :card_number, :expiry_date, :ccv, :amount)
        """)
        conn.execute(insert_query, user_id=user_id, card_number=card_number, expiry_date=expiry_date, ccv=ccv, amount=amount)

        # Update user's balance in the 'users' table
        update_query = text("""
            UPDATE users
            SET balance = balance + :amount
            WHERE user_id = :user_id
        """)
        conn.execute(update_query, amount=amount, user_id=user_id)

        # Record the transaction in the transactions table
        transaction_query = text("""
            INSERT INTO transactions (sender_account_number, amount, transaction_type, description)
            VALUES (:account_number, :amount, 'credit', 'Card Deposit')
        """)
        conn.execute(transaction_query, account_number=session.get('account_number'), amount=amount)

        flash(f'${amount} has been added to your account.', 'success')
        return redirect(url_for('account'))

    return render_template('add_money.html')


# Route for user logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('account_number', None)
    return redirect(url_for('home'))
  
@app.route('/admin/approve_users', methods=['GET'])
def approve_users_page():
    try:
        result = conn.execute(
            text('SELECT * FROM users WHERE approved = FALSE')
        ).fetchall()
        
        return render_template('approve_users.html', users=result)
    
    except Exception as e:
        print(f"Error fetching users: {e}")
        return render_template('admin_dashboard.html', error="Could not fetch unapproved users.", success=None)

@app.route('/admin/approve_user/<int:user_id>', methods=['POST'])
def approve_user(user_id):
    try:
        conn.execute(
            text('UPDATE users SET approved = TRUE WHERE user_id = :user_id'),
            {'user_id': user_id}
        )
        conn.commit()

        return redirect(url_for('approve_users_page'))

    except Exception as e:
        print(f"Error approving user: {e}")
        return redirect(url_for('approve_users_page'), error="Could not approve user.")

@app.route('/admin/dashboard')
def admin_dashboard():
    return render_template('admin_dashboard.html')

if __name__ == '__main__':
    app.run(debug=True)

@app.route('/admin/view_users', methods=['GET'])
def view_users():
    try:
        # Query to get all users
        users = conn.execute(text('SELECT * FROM users')).fetchall()

        return render_template('view_users.html', users=users)

    except Exception as e:
        print(f"Error fetching users: {e}")
        return render_template('admin_dashboard.html', error="Could not fetch users.", success=None)
