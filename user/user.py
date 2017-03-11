import json
import requests
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


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

    # decrypt package
    pub_key_b = RSA.import_key(result["key_B"])
    cipher_rsa = PKCS1_OAEP.new(pub_key_b)
    decrypted_hash = cipher_rsa.decrypt(result["encrypted"].encode())
    print(decrypted_hash)
    # TODO: incorrect length decrypt
    print(decrypted_hash)
