import os
def checkPassword(userid, password):
    conn = MySQLdb.connect(host="localhost", user="root", passwd = os.getenv("DB_PASSWORD"), db="users")
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE userid=%s", (userid,))
    row = cursor.fetchone()
    conn.close()
    if row is None:
        return False
    db_password = base64.b64decode(row[0]).decode('utf-8')
    return db_password == password