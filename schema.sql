DROP TABLE IF EXISTS access_log;
DROP TABLE IF EXISTS study_room_reservations;
DROP TABLE IF EXISTS study_rooms;
DROP TABLE IF EXISTS borrowing_records;
DROP TABLE IF EXISTS books;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS roles;

-- stores the RBAC roles in the system
CREATE TABLE roles (
    role_id INTEGER PRIMARY KEY AUTOINCREMENT,
    role_name TEXT NOT NULL UNIQUE,
    parent_role TEXT
);

-- stores user accounts
-- passwords are stored as hashes, not plain text
CREATE TABLE users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL,
    account_status TEXT NOT NULL,
    role_id INTEGER NOT NULL,
    FOREIGN KEY (role_id) REFERENCES roles(role_id)
);

-- stores the possible permissions/actions in the system
CREATE TABLE permissions (
    permission_id INTEGER PRIMARY KEY AUTOINCREMENT,
    permission_name TEXT NOT NULL UNIQUE,
    description TEXT
);

-- maps roles to permissions
-- this is the main RBAC authorization table
CREATE TABLE role_permissions (
    role_id INTEGER NOT NULL,
    permission_id INTEGER NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(role_id),
    FOREIGN KEY (permission_id) REFERENCES permissions(permission_id)
);

-- stores books in the library catalog
CREATE TABLE books (
    book_id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    author TEXT NOT NULL,
    status TEXT NOT NULL,
    current_holder_user_id INTEGER,
    hold_requested INTEGER DEFAULT 0,
    FOREIGN KEY (current_holder_user_id) REFERENCES users(user_id)
);

-- stores active and past borrowing records
CREATE TABLE borrowing_records (
    borrowing_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    book_id INTEGER NOT NULL,
    checkout_date TEXT NOT NULL,
    due_date TEXT NOT NULL,
    return_date TEXT,
    renewal_count INTEGER DEFAULT 0,
    borrowing_status TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (book_id) REFERENCES books(book_id)
);

-- stores study rooms available in the library
CREATE TABLE study_rooms (
    room_id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_name TEXT NOT NULL,
    capacity INTEGER NOT NULL,
    room_status TEXT NOT NULL
);

-- stores study room reservations
CREATE TABLE study_room_reservations (
    reservation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    room_id INTEGER NOT NULL,
    reservation_date TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    reservation_status TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (room_id) REFERENCES study_rooms(room_id)
);

-- stores authentication and authorization activity
-- this helps show denied access attempts for the project screenshots
CREATE TABLE access_log (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    action TEXT NOT NULL,
    result TEXT NOT NULL,
    reason TEXT,
    timestamp TEXT NOT NULL
);