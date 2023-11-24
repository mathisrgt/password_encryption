from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import csv
import hashlib
import os
import base64

app = Flask(__name__)
CORS(app)

# Path to the CSV file
csv_file_path = 'users.csv'

# Function to generate a random salt
def generate_salt():
    return os.urandom(16)

# Function to hash a password with a salt
def hash_password(password, salt):
    hasher = hashlib.sha256()
    password_with_salt = password.encode() + salt
    hasher.update(password_with_salt)
    return hasher.digest()

# Function to add data into a CSV file
def append_to_csv(username, salt, encrypted_password):
    with open(csv_file_path, 'a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([username, base64.b64encode(salt).decode(), encrypted_password])

@app.route('/hash', methods=['POST'])
def hash_password_endpoint():
    data = request.get_json()
    username = data['username']
    user_password = data['password']
    
    # Generate a random salt
    salt = generate_salt()
    
    # Hash the password with the salt
    hashed_password = hash_password(user_password, salt)

    # Send the hashed password for encryption to another server
    encryption_server_url = 'http://127.0.0.1:6000/encrypt'
    response = requests.post(encryption_server_url, json={'hashed_password': base64.b64encode(hashed_password).decode()})
    if response.status_code == 200:
        result = response.json()
        encrypted_password = result['encrypted_password']

        # Add the data to the CSV file
        append_to_csv(username, salt, encrypted_password)

        return {'message': 'User added successfully.'}
    else:
        return {'error': 'Error during password encryption.'}, 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']

    with open(csv_file_path, 'r') as file:
        reader = csv.reader(file)
        next(reader)  # Skip the header
        for row in reader:
            if row[0] == username:
                stored_salt = base64.b64decode(row[1])
                stored_encrypted_password = row[2]

                # Hash the provided password with the stored salt
                hashed_password = hash_password(password, stored_salt)
                
                # Verify if the password matches
                encryption_server_url = 'http://127.0.0.1:6000/encrypt'
                response = requests.post(encryption_server_url, json={'hashed_password': base64.b64encode(hashed_password).decode()})
                
                if response.status_code == 200:
                    result = response.json()
                    encrypted_password = result['encrypted_password']

                    if encrypted_password == stored_encrypted_password:
                        return jsonify({'message': 'Successful login.'})
                    else:
                        return jsonify({'error': 'Incorrect password.'}), 401
                else:
                    return jsonify({'error': 'Error during password encryption.'}), 500

        return jsonify({'error': 'Username not found.'}), 404

if __name__ == '__main__':
    app.run(port=5000)
