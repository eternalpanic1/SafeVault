import os
import getpass
from dotenv import load_dotenv
from supabase import create_client, Client
from cryptography.fernet import Fernet
from flask import Flask, render_template, request, redirect, url_for, session


app = Flask(__name__)
app.secret_key = '\xfd{H\xe5<\x95\xf9\xe3\x96.5\xd1\x01O<!\xd5\xa2\xa0\x9fR"\xa1\xa8'


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    if 'user_email' in session:
        email = ''
        return render_template('dashboard.html', email=email)
    else:
        return redirect(url_for('signin'))


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

def encrypt_password(user_key, password):
    cipher_suite = Fernet(user_key)
    encrypted_password = cipher_suite.encrypt(password.encode())
    return encrypted_password.decode()

def decrypt_password(user_key, encrypted_password):
    cipher_suite = Fernet(user_key)
    decrypted_password = cipher_suite.decrypt(encrypted_password.encode())
    return decrypted_password.decode()


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


def insert_password(username, website, password):
    email = curr_user[0]
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


def update_password(username, website, new_password):
    email = curr_user[0]
    user_key = load_user_fernet_key(email)
    if user_key:
        response = supabase.table('passwords').select('*').match({'user_email': email, 'website': website, 'username': username}).execute()
        encrypted_new_password = encrypt_password(user_key, new_password)

        response = supabase.table('passwords').update({'password': encrypted_new_password}).eq('username', username).execute()
        return "Password updated successfully"
    else:
        return "User not found."


def delete_password(website, username):
    email = curr_user[0]
    user_key = load_user_fernet_key(email)
    if user_key:
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
        return "User Key Error "


#------------- USER AUTHENTICATION ------------

def isNewUser(email):
    existing_users, count = supabase.table('users').select('*').match({'email':email}).execute()
    if existing_users[1]:
        return False
    return True


def signup(email, password, confirm_password):
    if isNewUser(email):
        if password != confirm_password:
            return "Passwords do not match. Signup canceled."
        
        try:
            res = supabase.auth.sign_up({
                "email": email,
                "password": confirm_password,
            })
    
            data, count = supabase.table('users').insert({'email': email}).execute()
            
            with open('keys.env', 'a') as key_file:
                key_file.write(f'{email},{new_key()}\n')

            return "Signup successful."
        
        except Exception as e:
            return f"Signup failed. {e}"

    else:
        return "User already registered. Please SignIn"


@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        try:
            data = supabase.auth.sign_in_with_password({"email": email, "password": password})
            curr_user.append(email)
            return redirect(url_for('dashboard'))

        except Exception as e:
            return render_template('failure.html', message=f"Signin failed. {e}")
    else:
        return render_template('signin.html') 


@app.route('/signup', methods = ['GET', 'POST'])
def signup_route():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        result = signup(email, password, confirm_password)
        if "Password inserted successfully" in result:
            return render_template('success.html', message=result)
        else:
            return render_template('failure.html', message=result)

    else:
        return render_template('signup.html')


@app.route('/insert_password', methods=['GET','POST'])
def insert_password_route():
    if request.method == 'POST':
        username = request.form['username']
        website = request.form['website']
        password = request.form['password']
        result = insert_password(username, website, password)
        
        if "Password inserted successfully" in result:
            return render_template('success.html', message=result)
        else:
            return render_template('failure.html', message=result)
    else:
        return render_template('insert_password.html')


@app.route('/update_password', methods=['GET','POST'])
def update_password_route():
    email = curr_user[0]
    if request.method == 'POST':
        username = request.form['username']
        website = request.form['website']
        password = request.form['new_password']
        result = update_password(username, website, password)
        
        if "Password updated successfully" in result:
            return render_template('success.html', message=result)
        else:
            return render_template('failure.html', message=result)
    else:
        return render_template('update.html')


@app.route('/delete_password', methods=['GET','POST'])
def delete_password_route():
    if request.method == 'POST':
        email = curr_user[0]
        website = request.form['website']
        username = request.form['username']

        result = delete_password(website, username)

        return render_template('failure.html', message=result)
    else:
        return render_template('delete.html')


@app.route('/display_passwords', methods=['GET', 'POST'])
def display_password_route():
        email = curr_user[0]
        user_key = load_user_fernet_key(email)

        if user_key:
            response = supabase.table('passwords').select('*').match({'user_email': email}).execute()
            passwords = []

            for entry in response.data:
                decrypted_password = decrypt_password(user_key, entry['password'])
                passwords.append({
                    'website': entry['website'],
                    'username': entry['username'],
                    'password': decrypted_password
                })

            return render_template('display.html', passwords=passwords)
        else:
            return render_template('failure.html', message="User not found.")


if __name__ == "__main__":
    
    load_dotenv('.env')
    url: str = os.getenv('SUPABASE_URL')
    key: str = os.getenv('SUPABASE_API')
    supabase: Client = create_client(url, key)
    
    curr_user = []
    app.run(debug=True)

    res = supabase.auth.sign_out()