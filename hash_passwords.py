import bcrypt
import json
import os
import sys

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

def register_user(username, password):
    """ Register a new user with a hashed password. """
    users = load_users()

    if username in users:
        print("❌ Username already exists. Try a different one.")
        return

    hashed_password = hash_password(password)
    users[username] = hashed_password
    save_users(users)
    print(f"✅ User '{username}' registered successfully!")

def verify_password(stored_hash, password):
    """ Verify if a given password matches the stored hash. """
    return bcrypt.checkpw(password.encode(), stored_hash.encode())

def login_user(username, password):
    """ Authenticate a user by verifying their hashed password. """
    users = load_users()

    if username not in users:
        print("❌ User not found! Please register first.")
        return

    if verify_password(users[username], password):
        print(f"✅ Login successful! Welcome, {username}.")
    else:
        print("❌ Incorrect password. Access denied.")

def main():
    """ Main function to handle command-line execution """
    if len(sys.argv) < 4:
        print("Usage:")
        print("  python hash_passwords.py register <username> <password>")
        print("  python hash_passwords.py login <username> <password>")
        return

    action = sys.argv[1].lower()
    username = sys.argv[2]
    password = sys.argv[3]

    if action == "register":
        register_user(username, password)
    elif action == "login":
        login_user(username, password)
    else:
        print("❌ Invalid action! Use 'register' or 'login'.")

if __name__ == "__main__":
    main()
