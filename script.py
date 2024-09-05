from pymongo import MongoClient
from cryptography.fernet import Fernet
from flask import Flask, render_template, request, redirect, url_for, session
import os
from dotenv import load_dotenv

app = Flask(__name__)
app.secret_key = os.urandom(32)

# Load environment variables
load_dotenv('.env')
mongo_uri = os.getenv('MONGO_URI')

# Initialize MongoDB client
client = MongoClient(mongo_uri)
db = client['your_database']  # Use your database name
users_collection = db['users']
passwords_collection = db['passwords']


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


# ------------ ENCRYPTION & DECRYPTION ------------
def new_key():
    key = Fernet.generate_key()
    return key.decode()


def load_user_fernet_key(email):
    user = users_collection.find_one({"email": email})
    return user['encryption_key'] if user else None


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
        user_passwords = passwords_collection.find({"user_email": email})

        print("{:<30} {:<30} {:<30}".format("Website", "Username", "Password"))
        print("-" * 100)

        for entry in user_passwords:
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
        passwords_collection.insert_one(data)
        return "Password inserted successfully."
    else:
        return "User not found."


def update_password(username, website, new_password):
    email = curr_user[0]
    user_key = load_user_fernet_key(email)
    if user_key:
        encrypted_new_password = encrypt_password(user_key, new_password)

        passwords_collection.update_one(
            {'user_email': email, 'website': website, 'username': username},
            {'$set': {'password': encrypted_new_password}}
        )
        return "Password updated successfully"
    else:
        return "User not found."


def delete_password(website, username):
    email = curr_user[0]
    user_key = load_user_fernet_key(email)
    if user_key:
        result = passwords_collection.delete_one(
            {'user_email': email, 'website': website, 'username': username}
        )
        if result.deleted_count:
            return "Password deleted successfully."
        else:
            return "Password not found."
    else:
        return "User Key Error"


#------------- USER AUTHENTICATION ------------

def isNewUser(email):
    existing_user = users_collection.find_one({"email": email})
    return existing_user is None


def signup(email, password, confirm_password):
    if isNewUser(email):
        if password != confirm_password:
            return "Passwords do not match. Signup canceled."
        
        try:
            # Store user data in MongoDB
            users_collection.insert_one({
                "email": email,
                "encryption_key": new_key()
            })

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

        user = users_collection.find_one({"email": email})
        if user:
            curr_user.append(email)
            return redirect(url_for('dashboard'))
        else:
            return render_template('failure.html', message="Signin failed. User not found.")
    else:
        return render_template('signin.html') 


@app.route('/signup', methods = ['GET', 'POST'])
def signup_route():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        result = signup(email, password, confirm_password)
        if "Signup successful." in result:
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
    curr_user = []
    app.run(debug=True)
