import bcrypt
import json
import os
import getpass

DB_FILE = "users.json"

def load_users():
    """ Load user database from a JSON file. """
    if not os.path.exists(DB_FILE):
        return {}
    try:
        with open(DB_FILE, "r") as file:
            return json.load(file)
    except json.JSONDecodeError:
        return {}

def save_users(users):
    """ Save user database to a JSON file. """
    try:
        with open(DB_FILE, "w") as file:
            json.dump(users, file, indent=4)
    except Exception as e:
        print(f"Error saving user data: {e}")

def hash_password(password):
    """ Hash a password using bcrypt with salting. """
    salt = bcrypt.gensalt(rounds=12)  # Increase work factor for better security
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()

def register_user():
    """ Register a new user with a hashed password. """
    users = load_users()
    username = input("Enter username: ").strip()

    if not username:
        print("Username cannot be empty.")
        return

    if username in users:
        print("Username already exists. Try a different one.")
        return

    password = getpass.getpass("Enter password: ").strip()
    confirm_password = getpass.getpass("Confirm password: ").strip()

    if not password:
        print("Password cannot be empty.")
        return

    if password != confirm_password:
        print("Passwords do not match! Try again.")
        return

    hashed_password = hash_password(password)

    users[username] = hashed_password
    save_users(users)
    print("✅ User registered successfully!")

def verify_password(stored_hash, password):
    """ Verify if a given password matches the stored hash. """
    return bcrypt.checkpw(password.encode(), stored_hash.encode())

def login_user():
    """ Authenticate a user by verifying their hashed password. """
    users = load_users()
    username = input("Enter username: ").strip()

    if username not in users:
        print("User not found! Please register first.")
        return

    password = getpass.getpass("Enter password: ").strip()

    if verify_password(users[username], password):
        print(f"✅ Login successful! Welcome, {username}.")
    else:
        print("❌ Incorrect password. Access denied.")

def main():
    while True:
        print("\n1. Register User")
        print("2. Login")
        print("3. Exit")

        choice = input("Select an option: ").strip()

        if choice == "1":
            register_user()
        elif choice == "2":
            login_user()
        elif choice == "3":
            print("🔒 Exiting program.")
            break
        else:
            print("❌ Invalid choice. Try again.")

if __name__ == "__main__":
    main()
