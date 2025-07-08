from master_password import verify_master_password
from breach_checker import check_password_breach
verify_master_password()
from cryptography.fernet import Fernet
from key import load_key

key = load_key()
fernet = Fernet(key)

# File to store password entries
PASSWORD_FILE = "passwords.txt"


# Encrypt and store password
def add(account, username, password):
    with open(PASSWORD_FILE, "a") as f:
        encrypted = fernet.encrypt(password.encode()).decode()
        f.write(f"{account}|{username}|{encrypted}\n")


# Decrypt and show all passwords
def view():
    try:
        with open(PASSWORD_FILE, "r") as f:
            for line in f:
                account, username, encrypted = line.strip().split("|")
                decrypted = fernet.decrypt(encrypted.encode()).decode()
                print(f"Account: {account}, Username: {username}, Password: {decrypted}")
    except FileNotFoundError:
        print("No passwords saved yet.")


# Search for an account
def search(account_name):
    found = False
    try:
        with open(PASSWORD_FILE, "r") as f:
            for line in f:
                account, username, encrypted = line.strip().split("|")
                if account.lower() == account_name.lower():
                    decrypted = fernet.decrypt(encrypted.encode()).decode()
                    print(f"Account: {account}, Username: {username}, Password: {decrypted}")
                    found = True
    except FileNotFoundError:
        print("Password file not found.")
    if not found:
        print("Account not found.")


# Delete an account
def delete(account_name):
    lines = []
    deleted = False
    try:
        with open(PASSWORD_FILE, "r") as f:
            lines = f.readlines()

        with open(PASSWORD_FILE, "w") as f:
            for line in lines:
                account, username, encrypted = line.strip().split("|")
                if account.lower() != account_name.lower():
                    f.write(line)
                else:
                    deleted = True

        if deleted:
            print("Account deleted.")
        else:
            print("Account not found.")
    except FileNotFoundError:
        print("Password file not found.")


def search_entry(filename='vault.txt'):
    search_term = input('Enter site or username to search for: ').lower()
    try:
        with open(filename, 'r') as file:
            entries = file.read().split('\n\n')
            found = False
            for entry in entries:
                if search_term in entry.lower():
                    print('\n--- Match Found ---')
                    print(entry)
                    print('------------')
                    found = True
            if not found:
                print('No matching entries found ')
    except FileNotFoundError:
        print(f'No vault file found at {filename}. Please add an entry first.')


def update_entry():
    account_name = input("Enter the account name to update: ")
    lines = []
    updated = False
    try:
        with open(PASSWORD_FILE, "r") as f:
            lines = f.readlines()

        with open(PASSWORD_FILE, "w") as f:
            for line in lines:
                account, username, encrypted = line.strip().split("|")
                if account.lower() == account_name.lower():
                    print(f"Current Username: {username}")
                    decrypted = fernet.decrypt(encrypted.encode()).decode()
                    print(f"Current Password: {decrypted}")
                    new_username = input("Enter new username (or press Enter to keep current): ")
                    new_password = input("Enter new password (or press Enter to keep current): ")

                    if new_username == "":
                        new_username = username
                    if new_password == "":
                        new_password = decrypted
                    encrypted_new = fernet.encrypt(new_password.encode()).decode()
                    f.write(f"{account}|{new_username}|{encrypted_new}\n")
                    updated = True
                else:
                    f.write(line)

        if updated:
            print("Account updated successfully.")
        else:
            print("Account not found.")
    except FileNotFoundError:
        print("Password file not found.")


def delete_entry():
    account_name = input("Enter the account name to delete: ")
    lines = []
    deleted = False
    try:
        with open(PASSWORD_FILE, "r") as f:
            lines = f.readlines()

        with open(PASSWORD_FILE, "w") as f:
            for line in lines:
                account, _, _ = line.strip().split("|")
                if account.lower() != account_name.lower():
                    f.write(line)
                else:
                    confirm = input(f"Are you sure you want to delete {account_name}? (yes/no): ")
                    if confirm.lower() == "yes":
                        deleted = True
                    else:
                        f.write(line)

        if deleted:
            print("Entry deleted.")
        else:
            print("Account not found or deletion canceled.")
    except FileNotFoundError:
        print("Password file not found.")


def export_entries(export_file='backup.txt'):
    try:
        with open(PASSWORD_FILE, 'r') as original, open(export_file, 'w') as backup:
            for line in original:
                backup.write(line)
        print(f'Entries exported successfully to {export_file}.')
    except FileNotFoundError:
        print('Password file not found.')

def import_entries(import_file='backup.txt'):
    try:
        with open(import_file, 'r') as backup, open(PASSWORD_FILE, 'a') as original:
            for line in backup:
                original.write(line)
        print(f'Entries imported successfully from {import_file}.')
    except:
        print('Backup file not found.')


def export_passwords(backup_file='backup_passwords.txt'):
    try:
        with open(PASSWORD_FILE, 'r') as original, open(backup_file, 'w') as backup:
            for line in original:
                backup.write(line)
        return True
    except FileNotFoundError:
        return False

def import_passwords(backup_file='backup_passwords.txt'):
    try:
        with open(backup_file, 'r') as backup, open(PASSWORD_FILE, 'a') as original:
            for line in backup:
                original.write(line)
        return True
    except FileNotFoundError:
        return False



# Main program menu
def main():
    while True:
        print("\nOptions: add | view | search | search_entry | update_entry | delete_entry | delete | export | import | quit")
        mode = input("What do you want to do? ").lower()

        if mode == "add":
            account = input("Account name: ")
            username = input("Username: ")
            password = input("Password: ")
            add(account, username, password)

        elif mode == "view":
            view()

        elif mode == "search":
            acc = input("Enter account to search: ")
            search(acc)

        elif mode == 'search_entry':
            search_entry()
        elif mode == 'update_entry':
            update_entry()
        elif mode == 'delete_entry':
            delete_entry()
        elif mode == "delete":
            acc = input("Enter account to delete: ")
            delete(acc)
        elif mode == 'export':
            export_entries()
        elif mode == 'import':
            import_entries()
        elif mode == "quit":
            break

        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()
