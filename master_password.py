import hashlib
import os

MASTER_FILE = 'master.key'


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def create_master_password():
    master = input('Create a master password: ')
    hashed = hash_password(master)
    with open(MASTER_FILE, 'w') as f:
        f.write(hashed)
    print('Master password set.')


def verify_master_password():
    if not os.path.exists(MASTER_FILE):
        create_master_password()
    else:
        with open(MASTER_FILE, 'r') as f:
            saved_hash = f.read()
        attempt = input('Enter master password: ')
        if hash_password(attempt) == saved_hash:
            print('Access granted.')
        else:
            print('Access denied.')
            exit()
