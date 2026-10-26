#!/usr/bin/env python3
"""Register users and verify logins using salted SHA-256 hashes."""

import getpass
import hashlib
import hmac
import secrets
from pathlib import Path

DATA_FILE = Path(__file__).with_name("users.txt")
SALT_BYTES = 16


def hash_password(password: str, salt: str) -> str:
    """Hash the concatenation password + salt with SHA-256."""
    return hashlib.sha256((password + salt).encode("utf-8")).hexdigest()


def load_users() -> dict[str, tuple[str, str]]:
    """Return records in the form {username: (salt, password_hash)}."""
    if not DATA_FILE.exists():
        return {}

    users = {}
    with DATA_FILE.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            record = line.strip()
            if not record:
                continue
            try:
                username, salt, password_hash = record.split("|")
            except ValueError as error:
                raise ValueError(
                    f"Invalid record on line {line_number} of {DATA_FILE}"
                ) from error
            users[username] = (salt, password_hash)
    return users


def register() -> None:
    """Create a new user record with a fresh random salt."""
    username = input("Login name: ").strip()
    if not username or "|" in username or "\n" in username:
        print("Registration failed: enter a nonempty name without '|'.")
        return

    users = load_users()
    if username in users:
        print("Registration failed: that login name already exists.")
        return

    password = getpass.getpass("New password: ")
    if not password:
        print("Registration failed: the password cannot be empty.")
        return

    salt = secrets.token_hex(SALT_BYTES)
    password_hash = hash_password(password, salt)
    with DATA_FILE.open("a", encoding="utf-8") as file:
        file.write(f"{username}|{salt}|{password_hash}\n")
    print(f"Registration successful for '{username}'.")


def login() -> bool:
    """Check a login name and password without revealing which part failed."""
    username = input("Login name: ").strip()
    password = getpass.getpass("Password: ")
    record = load_users().get(username)
    if record is None:
        print("Login failed: invalid login name or password.")
        return False

    salt, expected_hash = record
    supplied_hash = hash_password(password, salt)
    if hmac.compare_digest(supplied_hash, expected_hash):
        print(f"Login successful. Welcome, {username}!")
        return True

    print("Login failed: invalid login name or password.")
    return False


def main() -> None:
    actions = {"1": register, "2": login}
    while True:
        print("\n=== Salted Password Authentication ===")
        print("1. Register")
        print("2. Log in")
        print("3. Exit")
        choice = input("Select an option: ").strip()
        if choice == "3":
            print("Goodbye.")
            break
        action = actions.get(choice)
        if action is None:
            print("Invalid option. Please select 1, 2, or 3.")
        else:
            action()


if __name__ == "__main__":
    main()