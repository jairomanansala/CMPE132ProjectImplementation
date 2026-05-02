# provisioning, authentication, authorization, password hashing with bcrypt, deprovisioning, and basic library actions

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
from database import get_db_connection

app = Flask(__name__)
app.secret_key = "change-this-secret-key-for-class-project"

# bcrypt is used to hash and verify passwords
# plain-text passwords are never stored in the database
bcrypt = Bcrypt(app)

# simple project constraints
BORROW_LIMIT = 3
RENEWAL_LIMIT = 1


def log_access(username, action, result, reason):
    """
    Records authentication and authorization events.
    This helps show login attempts and denied access attempts for screenshots.
    """
    conn = get_db_connection()
    conn.execute(
        """
        INSERT INTO access_log (username, action, result, reason, timestamp)
        VALUES (?, ?, ?, ?, ?)
        """,
        (username, action, result, reason, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()


def get_current_user():
    """
    Returns the currently logged-in user.
    If no one is logged in, returns None.
    """
    if "user_id" not in session:
        return None

    conn = get_db_connection()
    user = conn.execute(
        """
        SELECT users.*, roles.role_name
        FROM users
        JOIN roles ON users.role_id = roles.role_id
        WHERE users.user_id = ?
        """,
        (session["user_id"],)
    ).fetchone()
    conn.close()

    return user


def get_user_permissions(user_id):
    """
    Gets all permissions assigned to the user's role.
    This is the main RBAC authorization lookup.
    """
    conn = get_db_connection()
    permissions = conn.execute(
        """
        SELECT permissions.permission_name
        FROM users
        JOIN role_permissions ON users.role_id = role_permissions.role_id
        JOIN permissions ON role_permissions.permission_id = permissions.permission_id
        WHERE users.user_id = ?
        """,
        (user_id,)
    ).fetchall()
    conn.close()

    return [p["permission_name"] for p in permissions]


def login_required():
    """
    Checks whether a user is currently logged in.
    """
    return "user_id" in session


def has_permission(permission_name):
    """
    Checks whether the current user has a specific permission.
    """
    user = get_current_user()

    if user is None:
        return False

    permissions = get_user_permissions(user["user_id"])
    return permission_name in permissions


def deny_access(action, reason="Missing permission"):
    """
    Logs a denied authorization attempt and shows the unauthorized page.
    """
    log_access(session.get("username", "unknown"), action, "denied", reason)
    return render_template("shared/unauthorized.html")


@app.route("/")
def index():
    """
    Sends logged-in users to the dashboard.
    Sends logged-out users to the login page.
    """
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Authenticates a user by checking the entered password against
    the bcrypt hash stored in the database.
    """
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db_connection()
        user = conn.execute(
            """
            SELECT users.*, roles.role_name
            FROM users
            JOIN roles ON users.role_id = roles.role_id
            WHERE username = ?
            """,
            (username,)
        ).fetchone()
        conn.close()

        if user is None:
            log_access(username, "login", "denied", "Username not found")
            flash("Invalid username or password.", "error")
            return redirect(url_for("login"))

        if user["account_status"] != "active":
            log_access(username, "login", "denied", "Account is disabled")
            flash("This account is disabled.", "error")
            return redirect(url_for("login"))

        # bcrypt compares the entered password to the stored hash.
        # the plain password is never stored or retrieved.
        if not bcrypt.check_password_hash(user["password_hash"], password):
            log_access(username, "login", "denied", "Incorrect password")
            flash("Invalid username or password.", "error")
            return redirect(url_for("login"))

        # a successful login creates a session.
        session["user_id"] = user["user_id"]
        session["username"] = user["username"]
        session["role_name"] = user["role_name"]

        log_access(username, "login", "granted", "Successful authentication")
        flash("Login successful.", "success")
        return redirect(url_for("dashboard"))

    return render_template("auth/login.html")


@app.route("/logout")
def logout():
    """
    Ends the current user session.
    """
    username = session.get("username", "unknown")
    session.clear()
    log_access(username, "logout", "granted", "User logged out")
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    """
    Shows the current user's account information and active RBAC permissions.
    """
    if not login_required():
        return redirect(url_for("login"))

    user = get_current_user()
    permissions = get_user_permissions(user["user_id"])

    return render_template(
        "shared/dashboard.html",
        user=user,
        permissions=permissions
    )


@app.route("/catalog")
def catalog():
    """
    Shows the book catalog.
    Users must have the view_catalog permission.
    """
    if not login_required():
        return redirect(url_for("login"))

    if not has_permission("view_catalog"):
        return deny_access("view_catalog")

    conn = get_db_connection()
    books = conn.execute("SELECT * FROM books").fetchall()
    conn.close()

    return render_template("member/catalog.html", books=books)


@app.route("/borrow/<int:book_id>", methods=["POST"])
def borrow_book(book_id):
    """
    Allows a member to borrow a book.
    The system checks the user's permission and book availability.
    """
    if not login_required():
        return redirect(url_for("login"))

    if not has_permission("borrow_book"):
        return deny_access("borrow_book")

    user = get_current_user()
    conn = get_db_connection()

    book = conn.execute(
        "SELECT * FROM books WHERE book_id = ?",
        (book_id,)
    ).fetchone()

    if book is None:
        conn.close()
        flash("Book not found.", "error")
        return redirect(url_for("catalog"))

    if book["status"] != "available":
        conn.close()
        flash("This book is not available.", "error")
        return redirect(url_for("catalog"))

    active_borrows = conn.execute(
        """
        SELECT COUNT(*) AS total
        FROM borrowing_records
        WHERE user_id = ? AND borrowing_status = 'active'
        """,
        (user["user_id"],)
    ).fetchone()

    if active_borrows["total"] >= BORROW_LIMIT:
        conn.close()
        flash("Borrowing limit reached.", "error")
        return redirect(url_for("catalog"))

    checkout_date = datetime.now().date()
    due_date = checkout_date + timedelta(days=14)

    conn.execute(
        """
        INSERT INTO borrowing_records
        (user_id, book_id, checkout_date, due_date, return_date, renewal_count, borrowing_status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (user["user_id"], book_id, str(checkout_date), str(due_date), None, 0, "active")
    )

    conn.execute(
        """
        UPDATE books
        SET status = 'checked_out', current_holder_user_id = ?
        WHERE book_id = ?
        """,
        (user["user_id"], book_id)
    )

    conn.commit()
    conn.close()

    log_access(user["username"], "borrow_book", "granted", f"Borrowed book ID {book_id}")
    flash("Book borrowed successfully.", "success")
    return redirect(url_for("catalog"))


@app.route("/rooms")
def rooms():
    """
    Shows study rooms available for reservation.
    """
    if not login_required():
        return redirect(url_for("login"))

    if not has_permission("reserve_room"):
        return deny_access("reserve_room")

    conn = get_db_connection()
    rooms_data = conn.execute("SELECT * FROM study_rooms").fetchall()
    conn.close()

    return render_template("member/rooms.html", rooms=rooms_data)


@app.route("/reserve/<int:room_id>", methods=["POST"])
def reserve_room(room_id):
    """
    Allows a member to reserve one study room.
    This project keeps the rule simple: one active reservation per user.
    """
    if not login_required():
        return redirect(url_for("login"))

    if not has_permission("reserve_room"):
        return deny_access("reserve_room")

    user = get_current_user()
    reservation_date = request.form["reservation_date"]
    start_time = request.form["start_time"]
    end_time = request.form["end_time"]

    conn = get_db_connection()

    active_reservation = conn.execute(
        """
        SELECT * FROM study_room_reservations
        WHERE user_id = ? AND reservation_status = 'active'
        """,
        (user["user_id"],)
    ).fetchone()

    if active_reservation is not None:
        conn.close()
        flash("You already have an active room reservation.", "error")
        return redirect(url_for("rooms"))

    room = conn.execute(
        "SELECT * FROM study_rooms WHERE room_id = ?",
        (room_id,)
    ).fetchone()

    if room is None or room["room_status"] != "available":
        conn.close()
        flash("This room is not available.", "error")
        return redirect(url_for("rooms"))

    conn.execute(
        """
        INSERT INTO study_room_reservations
        (user_id, room_id, reservation_date, start_time, end_time, reservation_status)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (user["user_id"], room_id, reservation_date, start_time, end_time, "active")
    )

    conn.execute(
        """
        UPDATE study_rooms
        SET room_status = 'unavailable'
        WHERE room_id = ?
        """,
        (room_id,)
    )

    conn.commit()
    conn.close()

    log_access(user["username"], "reserve_room", "granted", f"Reserved room ID {room_id}")
    flash("Study room reserved successfully.", "success")
    return redirect(url_for("rooms"))


@app.route("/renew")
def renew():
    """
    Shows active borrowed books for the current user.
    """
    if not login_required():
        return redirect(url_for("login"))

    if not has_permission("renew_book"):
        return deny_access("renew_book")

    user = get_current_user()
    conn = get_db_connection()

    records = conn.execute(
        """
        SELECT borrowing_records.*, books.title, books.hold_requested
        FROM borrowing_records
        JOIN books ON borrowing_records.book_id = books.book_id
        WHERE borrowing_records.user_id = ?
        AND borrowing_records.borrowing_status = 'active'
        """,
        (user["user_id"],)
    ).fetchall()

    conn.close()

    return render_template("member/renew.html", records=records)


@app.route("/renew/<int:borrowing_id>", methods=["POST"])
def renew_book(borrowing_id):
    """
    Renews a borrowed book if the current user owns the borrowing record,
    the renewal limit has not been reached, and no hold exists on the book.
    """
    if not login_required():
        return redirect(url_for("login"))

    if not has_permission("renew_book"):
        return deny_access("renew_book")

    user = get_current_user()
    conn = get_db_connection()

    record = conn.execute(
        """
        SELECT borrowing_records.*, books.hold_requested
        FROM borrowing_records
        JOIN books ON borrowing_records.book_id = books.book_id
        WHERE borrowing_records.borrowing_id = ?
        """,
        (borrowing_id,)
    ).fetchone()

    if record is None:
        conn.close()
        flash("Borrowing record not found.", "error")
        return redirect(url_for("renew"))

    if record["user_id"] != user["user_id"]:
        conn.close()
        return deny_access("renew_book", "User attempted to renew another user's book")

    if record["renewal_count"] >= RENEWAL_LIMIT:
        conn.close()
        flash("Renewal limit has already been reached.", "error")
        return redirect(url_for("renew"))

    if record["hold_requested"]:
        conn.close()
        flash("This book cannot be renewed because another user has requested it.", "error")
        return redirect(url_for("renew"))

    old_due_date = datetime.strptime(record["due_date"], "%Y-%m-%d").date()
    new_due_date = old_due_date + timedelta(days=14)

    conn.execute(
        """
        UPDATE borrowing_records
        SET due_date = ?, renewal_count = renewal_count + 1
        WHERE borrowing_id = ?
        """,
        (str(new_due_date), borrowing_id)
    )

    conn.commit()
    conn.close()

    log_access(user["username"], "renew_book", "granted", f"Renewed borrowing ID {borrowing_id}")
    flash("Book renewed successfully.", "success")
    return redirect(url_for("renew"))


@app.route("/users")
def users():
    """
    Admin-only page that lists users and password hashes.
    This helps demonstrate that passwords are stored as hashes in the database.
    """
    if not login_required():
        return redirect(url_for("login"))

    if not has_permission("manage_user_accounts"):
        return deny_access("manage_user_accounts")

    conn = get_db_connection()
    users_data = conn.execute(
        """
        SELECT users.*, roles.role_name
        FROM users
        JOIN roles ON users.role_id = roles.role_id
        ORDER BY users.user_id
        """
    ).fetchall()
    conn.close()

    return render_template("admin/users.html", users=users_data)


@app.route("/provision", methods=["GET", "POST"])
def provision():
    """
    Admin-only provisioning page.
    Creates a new user and stores a bcrypt hash of the password.
    """
    if not login_required():
        return redirect(url_for("login"))

    if not has_permission("manage_user_accounts"):
        return deny_access("provision_user")

    conn = get_db_connection()

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        full_name = request.form["full_name"]
        email = request.form["email"]
        role_id = request.form["role_id"]

        # hash the password using bcrypt before saving it
        password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

        try:
            conn.execute(
                """
                INSERT INTO users
                (username, password_hash, full_name, email, account_status, role_id)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (username, password_hash, full_name, email, "active", role_id)
            )
            conn.commit()

            log_access(session.get("username"), "provision_user", "granted", f"Created user {username}")
            flash("User provisioned successfully.", "success")
            return redirect(url_for("users"))

        except Exception:
            flash("Could not create user. The username may already exist.", "error")

    roles = conn.execute(
        "SELECT * FROM roles ORDER BY role_id"
    ).fetchall()

    conn.close()

    return render_template("admin/provision.html", roles=roles)


@app.route("/deprovision/<int:user_id>", methods=["POST"])
def deprovision_user(user_id):
    """
    Admin-only deprovisioning route.
    Instead of deleting a user, it disables the account.
    """
    if not login_required():
        return redirect(url_for("login"))

    if not has_permission("deprovision_users"):
        return deny_access("deprovision_user")

    current_user = get_current_user()

    if current_user["user_id"] == user_id:
        flash("You cannot disable your own account while logged in.", "error")
        return redirect(url_for("users"))

    conn = get_db_connection()

    target_user = conn.execute(
        "SELECT * FROM users WHERE user_id = ?",
        (user_id,)
    ).fetchone()

    if target_user is None:
        conn.close()
        flash("User not found.", "error")
        return redirect(url_for("users"))

    conn.execute(
        """
        UPDATE users
        SET account_status = 'disabled'
        WHERE user_id = ?
        """,
        (user_id,)
    )

    conn.commit()
    conn.close()

    log_access(
        current_user["username"],
        "deprovision_user",
        "granted",
        f"Disabled user {target_user['username']}"
    )

    flash("User account disabled successfully.", "success")
    return redirect(url_for("users"))


if __name__ == "__main__":
    app.run(debug=True)