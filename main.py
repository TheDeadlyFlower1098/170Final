from flask import Flask, render_template, request, redirect, url_for, flash, session
from sqlalchemy import create_engine, text
import hashlib

app = Flask(__name__)

con_str = "mysql://root:cset155@localhost/bank"
engine = create_engine(con_str, echo=True)
conn = engine.connect()

app.secret_key = 'your_secret_key_here'

@app.route('/')
def home():
    return render_template('home.html')


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
            text('SELECT user_id, password_hash, approved, account_number FROM users WHERE username = :username'),
            {'username': username}
        ).fetchone()

        if result:
            # Extract user details
            user_id, stored_password_hash, is_approved, account_number = result
            print(f"Stored password hash: '{stored_password_hash}'")
            print(f"User approved: {is_approved}")

            # Check if the user is approved
            if not is_approved:
                print("User not approved")
                return render_template('login.html', error="Your account is not approved yet.", success=None)

            # Hash the entered password using sha256 to match the stored hash
            hashed_input_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
            print(f"Hashed entered password: '{hashed_input_password}'")

            # Compare hashed password
            if stored_password_hash == hashed_input_password:
                print("Login successful")

                # Store user information in session
                session['user_id'] = user_id
                session['username'] = username
                session['account_number'] = account_number

                return redirect(url_for('home'))  # Redirect to the home page or another page
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
                return render_template('admin_dashboard.html')
            else:
                print("Password mismatch")
                return render_template('admin_login.html', error="Invalid password", success=None)
        else:
            print("User not found")
            return render_template('admin_login.html', error="User not found", success=None)

    except Exception as e:
        print(f"Error occurred during login: {e}")
        return render_template('admin_login.html', error="Login failed. Please try again.", success=None)

@app.route('/account')
def account_page():
    if 'username' not in session:
        return redirect(url_for('login_page'))

    username = session['username']
    
    result = conn.execute(
        text("SELECT * FROM users WHERE username = :username"),
        {'username': username}
    ).fetchone()

    if result:
        user_info = {
            'username': result.username,
            'first_name': result.first_name,
            'last_name': result.last_name,
            'ssn': result.ssn,
            'address': result.address,
            'phone_number': result.phone_number,
            'account_number': result.account_number,
            'balance': result.balance
        }
        return render_template('account.html', user=user_info)
    else:
        return redirect(url_for('login_page'))

@app.route('/add_money', methods=['POST'])
def add_money():
    if 'username' not in session:
        return redirect(url_for('login_page'))

    username = session['username']
    amount = request.form.get('amount', type=float)

    if amount is None or amount <= 0:
        flash("Invalid amount entered.", "error")
        return redirect(url_for('account_page'))

    # Simulate transaction success (pretend the card is valid)
    conn.execute(
        text("UPDATE users SET balance = balance + :amount WHERE username = :username"),
        {'amount': amount, 'username': username}
    )
    conn.commit()

    flash(f"${amount:.2f} has been added to your account!", "success")
    return redirect(url_for('account_page'))


@app.route('/transfer_money', methods=['POST'])
def transfer_money():
    if 'username' not in session:
        return redirect(url_for('login_page'))

    sender_username = session['username']
    recipient_account = request.form['recipient_account']
    transfer_amount = request.form.get('transfer_amount', type=float)

    if transfer_amount is None or transfer_amount <= 0:
        flash("Invalid transfer amount.", "error")
        return redirect(url_for('account_page'))

    # Check sender's balance
    sender_result = conn.execute(
        text("SELECT balance FROM users WHERE username = :username"),
        {'username': sender_username}
    ).fetchone()

    if sender_result is None or sender_result.balance < transfer_amount:
        flash("Insufficient balance for this transaction.", "error")
        return redirect(url_for('account_page'))

    # Check if recipient exists
    recipient_result = conn.execute(
        text("SELECT * FROM users WHERE account_number = :recipient_account"),
        {'recipient_account': recipient_account}
    ).fetchone()

    if recipient_result is None:
        flash("Recipient account does not exist.", "error")
        return redirect(url_for('account_page'))

    # Perform transaction
    conn.execute(
        text("UPDATE users SET balance = balance - :amount WHERE username = :username"),
        {'amount': transfer_amount, 'username': sender_username}
    )

    conn.execute(
        text("UPDATE users SET balance = balance + :amount WHERE account_number = :recipient_account"),
        {'amount': transfer_amount, 'recipient_account': recipient_account}
    )

    conn.commit()

    flash(f"Successfully sent ${transfer_amount:.2f} to account {recipient_account}.", "success")
    return redirect(url_for('account_page'))

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


@app.route('/admin/view_users', methods=['GET'])
def view_users():
    try:
        users = conn.execute(text('SELECT * FROM users')).fetchall()

        return render_template('view_users.html', users=users)

    except Exception as e:
        print(f"Error fetching users: {e}")
        return render_template('admin_dashboard.html', error="Could not fetch users.", success=None)

if __name__ == '__main__':
    app.run(debug=True)

