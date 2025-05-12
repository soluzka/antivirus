import getpass
from security.web_auth import set_password

if __name__ == "__main__":
    print("Set admin password for Antivirus Dashboard")
    pw1 = getpass.getpass("Enter new password: ")
    pw2 = getpass.getpass("Confirm new password: ")
    if pw1 != pw2:
        print("Passwords do not match.")
    elif len(pw1) < 8:
        print("Password must be at least 8 characters.")
    else:
        set_password(pw1)
        print("Admin password set successfully.")
