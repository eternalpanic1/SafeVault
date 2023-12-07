import os
import getpass
from dotenv import load_dotenv
from supabase import create_client, Client
from cryptography.fernet import Fernet


# ------------ ENCRYPTION & DECRYPTION ------------

def new_key():
    key = Fernet.generate_key()
    return key.decode()


def load_user_fernet_key(email):
    with open('keys.env', 'r') as key_file:
        for line in key_file:
            stored_email, user_key = line.strip().split(',')
            if stored_email == email:
                return user_key
    return None

# Function to encrypt a plaintext password using the user's Fernet key
def encrypt_password(user_key, password):
    cipher_suite = Fernet(user_key)
    encrypted_password = cipher_suite.encrypt(password.encode())
    return encrypted_password.decode()

# Function to decrypt an encrypted password using the user's Fernet key
def decrypt_password(user_key, encrypted_password):
    cipher_suite = Fernet(user_key)
    decrypted_password = cipher_suite.decrypt(encrypted_password.encode())
    return decrypted_password.decode()


# Function to display all stored passwords of a user
def display_passwords(email):
    user_key = load_user_fernet_key(email)
    if user_key:
        response = supabase.table('passwords').select('*').match({'user_email': email}).execute()

        print("{:<30} {:<30} {:<30}".format("Website", "Username", "Password"))
        print("-" * 100)

        for entry in response.data:
            decrypted_password = decrypt_password(user_key, entry['password'])
            print("{:<30} {:<30} {:<30}".format(entry['website'], entry['username'], decrypted_password))

        return True
    else:
        return "User not found."


# Function to insert a new password
def insert_password(email):
    website = input("Enter the website: ")
    username = input("Enter the username: ")
    password = getpass.getpass("Enter the password: ")

    user_key = load_user_fernet_key(email)
    if user_key:
        encrypted_password = encrypt_password(user_key, password)
        data = {
            'user_email': email,
            'website': website,
            'username': username,
            'password': encrypted_password
        }
        response = supabase.table('passwords').insert([data]).execute()
        return "Password inserted successfully."
    else:
        return "User not found."


def update_password(email):
    user_key = load_user_fernet_key(email)
    if user_key:
        website = input("Enter the website: ")
        username = input("Enter the username: ")
        new_password = getpass.getpass("Enter the new password: ")

        response = supabase.table('passwords').select('*').match({'user_email': email, 'website': website, 'username': username}).execute()
        encrypted_new_password = encrypt_password(user_key, new_password)

        response = supabase.table('passwords').update({'password': encrypted_new_password}).eq('username', username).execute()

    else:
        return "User not found."


def delete_password(email):
    user_key = load_user_fernet_key(email)
    if user_key:
        website = input("Enter the website: ")
        username = input("Enter the username: ")

        existing_password = supabase.table('passwords').select('*').match({'user_email': email, 'website': website, 'username': username}).execute()

        if existing_password.data:
            entry_id = existing_password.data[0]['id']
            response = supabase.table('passwords').delete().eq('id', entry_id).execute()

            if response.data:
                return "Password deleted successfully."
            else:
                return "Failed to delete password."
        else:
            return "Password not found."
    else:
        return "User's "



#------------- USER AUTHENTICATION ------------

def isNewUser(email):
    existing_users, count = supabase.table('users').select('*').match({'email':email}).execute()
    if existing_users[1]:
        return False
    return True


def signup():
    email = input("Enter your EmailID: ")

    if isNewUser(email):
        password = getpass.getpass("Enter your Master Password: ")
        password2 = getpass.getpass("Confirm your Master Password: ")

        if password != password2:
            if input("Passwords do not match.. Do you want to retry?(Y/N): ") in {'Y','y'}:
                signup()
            else:
                return "Passwords do not match. Signup canceled."
        
        try:
            res = supabase.auth.sign_up({
                "email": email,
                "password": password2,
            })
    
            data, count = supabase.table('users').insert({'email': email}).execute()
            
            with open('keys.env', 'a') as key_file:
                key_file.write(f'{email},{new_key()}\n')

            return "Signup successful."
        
        except Exception as e:
            return f"Signup failed. {e}"

    else:
        return "User already registered. Please SignIn"


def signin():
    email = input("Enter your EmailID: ")
    password = getpass.getpass("Enter your password: ")
    try:
        data = supabase.auth.sign_in_with_password({"email": email, "password": password})
        session = supabase.auth.get_session()
        return (True, email)
    except Exception as e:
        return (False, f"Signin failed. {e}")



if __name__ == "__main__":
    load_dotenv('.env')
    url: str = os.getenv('SUPABASE_URL')
    key: str = os.getenv('SUPABASE_API')
    supabase: Client = create_client(url, key)
    
    print("\nWelcome to the Password Manager!")

    while True:
        print("\nOptions:")
        print("1. Sign In")
        print("2. Sign Up")
        print("3. Exit")

        choice = input("Select an option (1/2/3): ")

        if choice == '1':
            session = signin()
            if session[0]:
                email = session[1]
                print(f"\nWelcome, {email}!")
                while True:
                    print("\nOperations:")
                    print("1. Insert Password")
                    print("2. Display Passwords")
                    print("3. Update Password")
                    print("4. Delete Password")
                    print("5. Exit")

                    operation = input("Select an operation (1/2/3/4/5): ")

                    if operation == '1':
                        insert_password(email)
                    elif operation == '2':
                        display_passwords(email)
                    elif operation == '3':
                        update_password(email)
                    elif operation == '4':
                        delete_password(email)
                    elif operation == '5':
                        print("Signing out...")
                        res = supabase.auth.sign_out()
                        break
                    else:
                        print("Invalid operation. Please select again.")

                else:
                    print(session[1])

        elif choice == '2':
            result = signup()
            print(result)

        elif choice == '3':
            print("Exiting. Goodbye!")
            break

        else:
            print("Invalid choice. Please select again.")

    res = supabase.auth.sign_out()