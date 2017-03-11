import json
import requests
import socket
import base64

from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5


def generate_rsa_keys(length):
    rsa_keys = RSA.generate(length)
    private_key = rsa_keys.exportKey()
    private_key = private_key.decode("utf-8")
    public_key = rsa_keys.publickey().exportKey()
    public_key = public_key.decode("utf-8")
    return private_key, public_key


if __name__ == "__main__":
    # generate keys
    keys = generate_rsa_keys(2048)

    # get ip
    ip = socket.gethostbyname(socket.gethostname())

    # call receive_user_info
    url = "http://192.168.0.16:8080/receive_user_info"
    result = requests.get(url, params={
        "public_key_u": keys[1],
        "identity_u": "USER",
        "ip_u": ip,
        "card_number": "1111-1111-1111-1111"
    })
    print(result.text)

    # call send_user_certificate
    url = "http://192.168.0.16:8080/send_user_certificate"
    result = json.loads(requests.get(url).text)
    print(json.dumps(result, sort_keys=True, indent=4))

    # build hash
    hash_builder = SHA1.new()
    hash_builder.update(result["identity_B"].encode())
    hash_builder.update(result["identity_U"].encode())
    hash_builder.update(result["ip_U"].encode())
    hash_builder.update(result["key_B"].encode())
    hash_builder.update(result["key_U"].encode())
    hash_builder.update(result["exp_date"].encode())
    hash_builder.update(result["balance"].encode())

    # check signature
    signature_decoded = base64.b64decode(result["signature"])
    pub_key_b = RSA.import_key(result["key_B"].encode())
    verifier = PKCS1_v1_5.new(pub_key_b)

    authenticated = False
    if verifier.verify(hash_builder, signature_decoded):
        authenticated = True

