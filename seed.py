
from flask import Flask
from flask_bcrypt import Bcrypt
from database import get_db_connection, init_db

# a small Flask app is created here only so Flask-Bcrypt can generate password hashes
app = Flask(__name__)
bcrypt = Bcrypt(app)


def make_hash(password):
    """
    Creates a bcrypt hash for the given password.
    The result is decoded into a string so it can be stored in SQLite.
    """
    return bcrypt.generate_password_hash(password).decode("utf-8")


def seed_database():
    """
    Creates the database tables and inserts sample data.
    Running this file resets the database.
    """
    init_db()
    conn = get_db_connection()

    # RBAC roles
    roles = [
        ("User", None),
        ("Member", "User"),
        ("Librarian", "User"),
        ("Administrator", "User")
    ]

    conn.executemany(
        "INSERT INTO roles (role_name, parent_role) VALUES (?, ?)",
        roles
    )

    # permissions
    permissions = [
        ("view_catalog", "View available books in the catalog"),
        ("borrow_book", "Borrow an available book"),
        ("view_borrow_history", "View borrowing history"),
        ("reserve_room", "Create a study room reservation"),
        ("cancel_own_reservation", "Cancel personal room reservation"),
        ("renew_book", "Renew an eligible borrowed book"),
        ("manage_book_records", "Add or update book records"),
        ("manage_user_accounts", "Manage user accounts"),
        ("deprovision_users", "Disable user accounts")
    ]

    conn.executemany(
        "INSERT INTO permissions (permission_name, description) VALUES (?, ?)",
        permissions
    )

    # roles to permissions
    role_permissions = {
        "User": [
            "view_catalog"
        ],

        "Member": [
            "view_catalog",
            "borrow_book",
            "view_borrow_history",
            "reserve_room",
            "cancel_own_reservation",
            "renew_book"
        ],

        "Librarian": [
            "view_catalog",
            "view_borrow_history",
            "manage_book_records"
        ],

        "Administrator": [
            "view_catalog",
            "view_borrow_history",
            "manage_book_records",
            "manage_user_accounts",
            "deprovision_users"
        ]
    }

    for role_name, permission_names in role_permissions.items():
        role = conn.execute(
            "SELECT role_id FROM roles WHERE role_name = ?",
            (role_name,)
        ).fetchone()

        for permission_name in permission_names:
            permission = conn.execute(
                "SELECT permission_id FROM permissions WHERE permission_name = ?",
                (permission_name,)
            ).fetchone()

            conn.execute(
                "INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)",
                (role["role_id"], permission["permission_id"])
            )

    # get role IDs for starter users
    admin_role = conn.execute(
        "SELECT role_id FROM roles WHERE role_name = 'Administrator'"
    ).fetchone()

    member_role = conn.execute(
        "SELECT role_id FROM roles WHERE role_name = 'Member'"
    ).fetchone()

    librarian_role = conn.execute(
        "SELECT role_id FROM roles WHERE role_name = 'Librarian'"
    ).fetchone()

    # sample users
    # admin1, member1, and member2 use the same password.
    # their stored hashes will still be different because bcrypt uses salts
    starter_users = [
        (
            "admin1",
            make_hash("Password123"),
            "Admin User",
            "admin1@sjsu.edu",
            "active",
            admin_role["role_id"]
        ),
        (
            "member1",
            make_hash("Password123"),
            "Jairo Manansala",
            "member1@sjsu.edu",
            "active",
            member_role["role_id"]
        ),
        (
            "member2",
            make_hash("Password123"),
            "Second Member",
            "member2@sjsu.edu",
            "active",
            member_role["role_id"]
        ),
        (
            "librarian1",
            make_hash("Library123"),
            "Library Staff",
            "librarian1@sjsu.edu",
            "active",
            librarian_role["role_id"]
        )
    ]

    conn.executemany(
        """
        INSERT INTO users
        (username, password_hash, full_name, email, account_status, role_id)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        starter_users
    )

    # sample books
    books = [
        ("Rainbow Fish", "J. Manansala", "available", None, 0),
        ("Introduction to Cybersecurity", "SJSUL Press", "available", None, 0),
        ("Database Systems Basics", "CMPE Library", "checked_out", 2, 1)
    ]

    conn.executemany(
        """
        INSERT INTO books
        (title, author, status, current_holder_user_id, hold_requested)
        VALUES (?, ?, ?, ?, ?)
        """,
        books
    )

    # existing borrowing record for member1
    # this lets the renew page show a borrowed book immediately
    conn.execute(
        """
        INSERT INTO borrowing_records
        (user_id, book_id, checkout_date, due_date, return_date, renewal_count, borrowing_status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (2, 3, "2026-04-01", "2026-04-15", None, 0, "active")
    )

    # insert study rooms
    rooms = [
        ("Study Room A", 4, "available"),
        ("Study Room B", 6, "available"),
        ("Study Room C", 10, "available")
    ]

    conn.executemany(
        """
        INSERT INTO study_rooms
        (room_name, capacity, room_status)
        VALUES (?, ?, ?)
        """,
        rooms
    )

    conn.commit()
    conn.close()

    print("Database created and seeded successfully.")
    print("Admin login: admin1 / Password123")
    print("Member login: member1 / Password123")
    print("Member 2 login: member2 / Password123")
    print("Librarian login: librarian1 / Library123")


if __name__ == "__main__":
    seed_database()