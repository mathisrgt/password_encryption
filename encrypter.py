from flask import Flask, request, jsonify
from flask_cors import CORS
import base64
import tink
from tink import daead, cleartext_keyset_handle

app = Flask(__name__)
CORS(app)

def init_tink_deterministic():
    daead.register()
    keyset = r"""{
        "key": [{
            "keyData": {
                "keyMaterialType": "SYMMETRIC",
                "typeUrl": "type.googleapis.com/google.crypto.tink.AesSivKey",
                "value": "EkAobOz+mL3XphMYHgMKitKTDANm69aQe0tgN82uYhT1tW07Q74fuyy7MoHN+WrZVvfTfCho5vC0Ai5d9nIa3exf"
            },
            "outputPrefixType": "TINK",
            "status": "ENABLED"
        }]
    }"""
    keyset_handle = cleartext_keyset_handle.read(tink.JsonKeysetReader(keyset))
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
