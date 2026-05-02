# database.py
# this file contains helper functions for connecting to the SQLite database

import sqlite3

DATABASE = "sjsul.db"

def get_db_connection():
    """
    Opens a connection to the SQLite database.
    row_factory allows us to access columns by name, like user["username"].
    """
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """
    Creates a fresh database using schema.sql.
    This is mainly used by seed.py when setting up the project.
    """
    conn = get_db_connection()

    with open("schema.sql", "r") as file:
        conn.executescript(file.read())

    conn.commit()
    conn.close()