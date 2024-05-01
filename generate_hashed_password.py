import bcrypt
import getpass

# Example of hashing a password
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Prompt the user for a password without echoing
password = getpass.getpass('Enter your password: ')
# Hashing and storing passwords
hashed_passwords = {f"user{1}": hash_password(password).decode('utf-8')}

# Output the hashed passwords
print(hashed_passwords)