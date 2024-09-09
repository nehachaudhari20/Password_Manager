import json
import getpass
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import secrets
import string

Password_file = "store_pass.json"
Key_file = 'aes_key.key'
PIN_file = 'pin_password.txt'

#generation of a random AES key.
def generate_key():
    #used to generate a string of size 32 bytes 
    key = os.urandom(32)
    with open(Key_file, 'wb') as KeyFile:
        KeyFile.write(key)

#load the AES key from a file
def load_key():
    if not os.path.exists(Key_file):
        generate_key()
    return open(Key_file, 'rb').read()

#encrypt the pass
def encrypt_password(password):
    key = load_key()
    Initialize_vector = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(Initialize_vector), backend = default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_password = padder.update(password.encode()) + padder.finalize()

    encrypted_password = encryptor.update(padded_password) + encryptor.finalize()
    return base64.urlsafe_b64encode(Initialize_vector +encrypted_password).decode('utf-8')

#decrypt the pass
def decrypt_password(encrypted_password):
    key = load_key()
    encrypted_password = base64.urlsafe_b64decode(encrypted_password)
    Initialize_vector = encrypted_password[:16]
    encrypted_password = encrypted_password[16:]

    cipher = Cipher(algorithms.AES(key), modes.CFB(Initialize_vector), backend = default_backend())
    decryptor = cipher.decryptor()

    decrypted_pass = decryptor.update(encrypted_password) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    decrypt_password = unpadder.update(decrypted_pass) + unpadder.finalize()
    return decrypt_password.decode()

#generate pin for authentication
def pin_password():
    pass_authentication = getpass.getpass("enter the PIN: ")
    with open(PIN_file, 'w') as file:
        file.write(pass_authentication)

#verify the pin
def verify_pin_password():
    if not os.path.exists(PIN_file):
        pin_password()
    pin = open(PIN_file,'r').read().strip()
    input_PIN = getpass.getpass("enter the PIN: ")
    return input_PIN == pin

#save acc info
def save_acc_info(account_name, username, encrypted_password):
    data = {}
    if os.path.exists(Password_file):
        try:
            with open(Password_file, 'r') as file:
                file_content = file.read().strip()
                if file_content:
                    data = json.loads(file_content)
        except json.JSONDecodeError:
            print("Error: JSON file is corrupted.")
        except IOError as e:
            print(f"Error reading file: {e}")

    data[account_name] = {
        'username' :username,
        'password' :encrypted_password
    }
    with open(Password_file,'w') as file:
        json.dump(data, file, indent = 4)

#add pass
def add_password():
    account_name = input("enter the account name: ")
    username = input("enter the username: ")
    password = getpass.getpass("enter the password: ")
    encrypted_password = encrypt_password(password)
    save_acc_info(account_name, username, encrypted_password)
    print("Password is saved")

def view_password():
    if not verify_pin_password():
        print("Invalid PIN!")
        return
    
    if os.path.exists(Password_file):
        with open(Password_file, 'r') as file:
            data = json.load(file)
        
        print("SAVED ACCOUNTS ARE:")
        for account, info in data.items():
            print(f"Account: {account}")
            print(f"Username: {info['username']}")
            print("Password: [Hidden]")
            print('-' * 40)

        reveal = input("Do you want to reveal passwords? (yes/no): ").strip().lower()
        if reveal == 'yes':
            for account, info in data.items():
                if verify_pin_password():
                    decrypted_password = decrypt_password(info['password'])
                    print(f"Account: {account}")
                    print(f"Username: {info['username']}")
                    print(f"Password: {decrypted_password}")
                else:
                    print("Invalid PIN!!.")
                    break
        else:
            print("passwords is hidden.")
    else:
        print("no password file found.")


"""#reveal pass
def reveal_password(account_name):
    if os.path.exists('passwords.json'):
        with open('passwords.json', 'r') as file:
            data = json.load(file)
        
        if account_name in data:
            pin_password = getpass.getpass("enter the pin")
            if validiate_pin_password(pin_password):
                encrypt_password = data[account_name]['password']
                print("Decrypted pass: {decrypt_password(encrypted_password)}")
            else:
                print("invalid pin")
        else:
            print("no account found")
    else:
        print("no password found")"""

#delete the password of a sepcific account
def delete_password():
    if not verify_pin_password():
        print("Authentication failed!")
        return
    
    account_name = input("enter the account name for the deletion of the password: ")
    if os.path.exists(Password_file):
        with open(Password_file, 'r') as file:
            data = json.load(file)

        if account_name in data:
            checkIf = input(f"Are you sure you want to delete the password for the account {account_name}? Y/N")
            if checkIf == 'Y':
                data[account_name]['password'] = None
                with open(Password_file, 'w') as file:
                    json.dump(data, file, indent = 4)
                print("password is deleted successfulyy")
            else:
                print("deletion not possible")
        else:
            print("ACCOUNT NOT FOUND")
    else:
        print("no password found")

#update the password
def update_password():
    if not verify_pin_password():
        print("authentication failed.")
        return
    
    account_name = input("Enter the account name to update the password: ")
    if os.path.exists(Password_file):
        with open(Password_file,'r') as file:
            data = json.load(file)

        if account_name in data:
            username = data[account_name]['username']
            print(f"current username: {username}")
            new_pass = getpass.getpass("Enter the new pass: ")
            encrypted_password = encrypt_password(new_pass)
            save_acc_info(account_name, username, encrypted_password)
            print("password updated successfully!")
        else:
            print("account not found. ")
    else:
        print("no password found ")

#generate random password
def generate_password(length = 8, complexity = 'hight'):
    if complexity == 'high':
        pass_char = string.ascii_letters + string.digits
    elif complexity == 'low':
        pass_char = string.ascii_letters
    else:
        pass_char = string.digits

    return ''.join(secrets.choice(pass_char) for _ in range(length))
    

##def validiate_pin_password(pin_password):
  ##  return pin_password == 'pin password'


def main():
    if not os.path.exists(Key_file):
        generate_key()

    ans = True
    while ans:
        print("TERMINAL PASSWORD GENERATOR")
        print("1. ADD PASSWORD")
        print("2. VIEW PASSWORD")
        print("3. UPDATE PASSWORD")
        print("4. DELETE PASSWORD")
        print("5. GENERATE RANDOM PASSWORD")
        print("6. EXIT")

        try:
            choice = int(input("Enter the choice to execute: "))

            if choice == 1:
                account_name = input("Enter the account name: ")
                username = input("Enter the username: ")
                password = getpass.getpass("Enter the password: ")
                encrypted_password = encrypt_password(password)
                save_acc_info(account_name, username, encrypted_password)

            elif choice == 2:
                view_password()

            elif choice == 3:
                update_password()

            elif choice == 4:
                delete_password()

            elif choice == 5:
                length = int(input("Enter the length of the password: "))
                complexity = input("Enter the complexity of the password (high/low/none): ").lower()
                generated_password = generate_password(length, complexity)
                print(f"Generated password: {generated_password}")
                
            elif choice == 6:
                print("THANK YOU")
                ans = False  # Exit the loop
                
            else:
                print("Invalid input number. ")

        except ValueError:
            print("Invalid input. Please enter a number.")

        except Exception as e:
            print(f"An unexpected error occurred: {e}")

        if ans:
            continue_choice = input("Do you want to continue? (true/false): ").strip().lower()
            ans = continue_choice == 'true'

if __name__ == '__main__':
    main()
