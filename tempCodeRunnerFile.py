from sqlalchemy import create_engine

engine = create_engine("mysql://root:cset155@localhost/bank")
try:
    conn = engine.connect()
    print("Database connected successfully!")
    conn.close()
except Exception as e:
    print(f"Database connection failed: {e}")