from flask import Flask, request, jsonify
from flask_cors import CORS
import base64
import tink
from tink import daead, cleartext_keyset_handle

app = Flask(__name__)
CORS(app)

def init_tink_deterministic():
    daead.register()
    # Load the keyset from a file
    with open('tink_keyset.json', 'r') as keyset_file:
        keyset_handle = cleartext_keyset_handle.read(tink.JsonKeysetReader(keyset_file.read()))
    return keyset_handle

KEYSET_HANDLE = init_tink_deterministic()

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.get_json()
    hashed_password = data['hashed_password'].encode()

    daead_primitive = KEYSET_HANDLE.primitive(daead.DeterministicAead)
    ciphertext = daead_primitive.encrypt_deterministically(hashed_password, b'')

    return jsonify({'encrypted_password': base64.b64encode(ciphertext).decode()})

if __name__ == '__main__':
    app.run(port=6000)
