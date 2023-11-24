from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import csv
import hashlib
import os
import base64

app = Flask(__name__)
CORS(app)

# Chemin du fichier CSV
csv_file_path = 'users.csv'

# Fonction pour générer un sel aléatoire
def generate_salt():
    return os.urandom(16)

# Fonction pour hacher un mot de passe avec un sel
def hash_password(password, salt):
    hasher = hashlib.sha256()
    password_with_salt = password.encode() + salt
    hasher.update(password_with_salt)
    return hasher.digest()

# Fonction pour ajouter des données dans un fichier CSV
def append_to_csv(username, salt, encrypted_password):
    with open(csv_file_path, 'a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([username, base64.b64encode(salt).decode(), encrypted_password])

# Fonction pour hacher un mot de passe avec un sel
def hash_password(password, salt):
    hasher = hashlib.sha256()
    password_with_salt = password.encode() + salt
    hasher.update(password_with_salt)
    return hasher.digest()

# Fonction pour ajouter des données dans un fichier CSV
def append_to_csv(username, salt, encrypted_password):
    with open(csv_file_path, 'a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([username, base64.b64encode(salt).decode(), encrypted_password])

@app.route('/hash', methods=['POST'])
def hash_password_endpoint():
    data = request.get_json()
    username = data['username']
    user_password = data['password']
    
    # Générer un sel aléatoire
    salt = generate_salt()
    
    # Hacher le mot de passe avec le sel
    hashed_password = hash_password(user_password, salt)

    # Envoi du mot de passe haché pour chiffrement à un autre serveur
    encryption_server_url = 'http://127.0.0.1:6000/encrypt'
    response = requests.post(encryption_server_url, json={'hashed_password': base64.b64encode(hashed_password).decode()})
    print(response)
    if response.status_code == 200:
        result = response.json()
        encrypted_password = result['encrypted_password']

        # Ajouter les données dans le fichier CSV
        append_to_csv(username, salt, encrypted_password)

        return {'message': 'Utilisateur ajouté avec succès.'}
    else:
        return {'error': 'Erreur lors du chiffrement du mot de passe.'}, 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']

    with open(csv_file_path, 'r') as file:
        reader = csv.reader(file)
        next(reader)  # Saute l'en-tête
        for row in reader:
            if row[0] == username:
                print(row[2])
                stored_salt = base64.b64decode(row[1])
                stored_encrypted_password = row[2]

                # Hacher le mot de passe fourni avec le sel stocké
                hashed_password = hash_password(password, stored_salt)
                
                # Vérifier si le mot de passe correspond
                encryption_server_url = 'http://127.0.0.1:6000/encrypt'
                response = requests.post(encryption_server_url, json={'hashed_password': base64.b64encode(hashed_password).decode()})
                print(response.json())
                
                if response.status_code == 200:
                    result = response.json()
                    encrypted_password = result['encrypted_password']

                    if encrypted_password == stored_encrypted_password:
                        return jsonify({'message': 'Connexion réussie.'})
                    else:
                        return jsonify({'error': 'Mot de passe incorrect.'}), 401
                else:
                    return jsonify({'error': 'Erreur lors du chiffrement du mot de passe.'}), 500

        return jsonify({'error': 'Nom d\'utilisateur introuvable.'}), 404

if __name__ == '__main__':
    app.run(port=5000)
