import hashlib
import os
import json
import logging
import secrets

class UserManager:
    def __init__(self, user_file='users.json'):
        self.user_file = user_file
        self.users = {}
        self._load_users()

        # First run (no users.json yet / empty store): create a single
        # account with a cryptographically random password instead of
        # seeding known demo credentials.
        if not self.users:
            self._initialize_first_run_user()

    def _initialize_first_run_user(self):
        """Create exactly one initial account, username "admin", with a
        cryptographically random password, and print it once so the
        operator can log in. This replaces the old fixed demo accounts
        (test/test, user1/password1, user2/password2)."""
        username = "admin"
        password = secrets.token_urlsafe(12)

        self._add_user(username, password)
        self._save_users()

        print("=" * 60)
        print("No users found - created a one-time initial account:")
        print(f"  Username: {username}")
        print(f"  Password: {password}")
        print("Save this password now; it is not stored anywhere in")
        print("plaintext and will not be shown again.")
        print("=" * 60)

    def _load_users(self):
        """Load users from file if it exists, otherwise start with empty dict"""
        try:
            with open(self.user_file, 'r') as f:
                self.users = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.users = {}

    def _save_users(self):
        """Save users to file"""
        with open(self.user_file, 'w') as f:
            json.dump(self.users, f)

    def _add_user(self, username, password):
        """Internal method to add a user with hashed password"""
        salt = os.urandom(32)
        
        # Create hash with salt
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000
        )
        
        # Store the user with salt and hash
        self.users[username] = {
            "salt": salt.hex(),
            "hash": key.hex()
        }

    def authenticate(self, username, password):
        # Logged at DEBUG (not printed) and does not distinguish "unknown
        # user" from "wrong password", to avoid aiding username enumeration
        # via server console/log output. Debug-level logging of the attempted
        # username is an accepted, low-risk tradeoff for a learning project.
        success = False

        if username in self.users:
            stored = self.users[username]
            salt = bytes.fromhex(stored["salt"])
            stored_hash = stored["hash"]

            # Hash the provided password with the same salt
            key = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt,
                100000
            )
            calculated_hash = key.hex()
            success = calculated_hash == stored_hash

        logging.debug(
            "Authentication attempt for user '%s': %s",
            username, "success" if success else "failed"
        )
        return success