import requests

# URL du serveur de hashage Flask
server_url = 'http://127.0.0.1:5000/hash'  # Remplacez par l'URL du serveur Flask

# Fonction pour envoyer une demande au serveur de hashage
def hash_password_with_server(username, password):
    data = {'username': username, 'password': password}

    response = requests.post(server_url, json=data)
    
    if response.status_code == 200:
        print("Demande réussie.")
        result = response.json()
        return result
    else:
        print("Erreur lors de la demande au serveur:", response.status_code, response.text)
        return None

# Exemple d'utilisation
username = "Alice"
user_password = "MotDePasse123"
response = hash_password_with_server(username, user_password)
if response:
    print(response)
