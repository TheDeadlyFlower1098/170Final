from flask import Flask, render_template, request, redirect, url_for, flash, session
from sqlalchemy import create_engine, text
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import random

app = Flask(__name__)

con_str = "mysql://root:cset155@localhost/bank"
engine = create_engine(con_str, echo=True)
conn = engine.connect()
app.secret_key = 'your_secret_key'

@app.route('/')
def home():
    return render_template('home.html')

# Route to show user's account details
@app.route('/account')
def account():
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirect if not logged in

    user_id = session['user_id']
    # Query user data
    query = text("SELECT * FROM users WHERE user_id = :user_id")
    result = conn.execute(query, user_id=user_id).fetchone()

    if result:
        user_info = {
            'username': result['username'],
            'first_name': result['first_name'],
            'last_name': result['last_name'],
            'ssn': result['ssn'],
            'address': result['address'],
            'phone_number': result['phone_number'],
            'account_number': result['account_number'],
            'balance': result['balance']
        }
        return render_template('account.html', user_info=user_info)
    else:
        flash('User not found', 'danger')
        return redirect(url_for('home'))

# Route to handle adding money to the account
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

# Route for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        query = text("SELECT * FROM users WHERE username = :username")
        result = conn.execute(query, username=username).fetchone()

        if result and check_password_hash(result['password_hash'], password):
            session['user_id'] = result['user_id']
            session['username'] = result['username']
            session['account_number'] = result['account_number']
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials', 'danger')

    return render_template('login.html')

# Route for user logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('account_number', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
