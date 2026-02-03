import os
def getConnection():
    return mysql.connector.connect(
        host="localhost",
        user="your_username",
        password = os.getenv("DB_PASSWORD"),
        database="your_database"
    )