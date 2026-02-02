import sqlite3

conn = sqlite3.connect("users.db")
cursor = conn.cursor()

def login(username, password):
    query = f"""
    SELECT * FROM users
    WHERE username = '{username}'
    AND password = '{password}'
    """
    print("Running:", query)
    return cursor.execute(query).fetchone()

# attacker input
user = "admin"
pwd = "' OR '1'='1"

result = login(user, pwd)

if result:
    print("Logged in!")
else:
    print("Access denied.")
