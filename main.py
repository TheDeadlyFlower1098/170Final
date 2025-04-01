from flask import Flask, render_template, request, redirect, url_for, flash
from sqlalchemy import create_engine, text
from werkzeug.security import generate_password_hash 

app = Flask(__name__) 

con_str = "mysql://root:cset155@localhost/bank"
engine = create_engine(con_str, echo=True)
conn = engine.connect() 

@app.route('/')
def home():
    return render_template('home.html')

# Run the Flask application in debug mode
if __name__ == '__main__':
    app.run(debug=True)