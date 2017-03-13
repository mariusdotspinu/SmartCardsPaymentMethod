import json
import requests
import socket
import base64
import uuid
import datetime

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


def generate_secret():
    return uuid.uuid4()


def generate_hash_chain(n):
    hash_chain=list()

    secret=generate_secret()
    hash_chain.append(secret)

    for i in range(0,n):
        h_builder = SHA1.new()
        h_builder.update(secret)
        secret=h_builder.hexdigest()
        hash_chain.append(secret)

    return hash_chain


if __name__ == "__main__":
    # generate keys

    # get ip
    ip = socket.gethostbyname(socket.gethostname())

    # call receive_user_info
    url = "http://192.168.0.16:8080/receive_user_info"
    keys = generate_rsa_keys(2048)
    c_u = requests.get(url, params={
        "public_key_u": keys[1],
        "identity_u": "USER",
        "ip_u": ip,
        "card_number": "1111-1111-1111-1111"
    })
    print(c_u.text)

    # call send_user_certificate
    url = "http://192.168.0.16:8080/send_user_certificate"
    c_u = json.loads(requests.get(url).text)
    print(json.dumps(c_u, sort_keys=True, indent=4))

    # build hash
    hash_builder = SHA1.new()
    hash_builder.update(c_u["identity_B"].encode())
    hash_builder.update(c_u["identity_U"].encode())
    hash_builder.update(c_u["ip_U"].encode())
    hash_builder.update(c_u["key_B"].encode())
    hash_builder.update(c_u["key_U"].encode())
    hash_builder.update(c_u["exp_date"].encode())
    hash_builder.update(c_u["balance"].encode())

    # check signature
    signature_decoded = base64.b64decode(c_u["signature"])
    pub_key_b = RSA.import_key(c_u["key_B"].encode())
    verifier = PKCS1_v1_5.new(pub_key_b)

    authenticated = False
    if verifier.verify(hash_builder, signature_decoded):
        authenticated = True

    if authenticated:
        n = 100
        hash_list = generate_hash_chain(n)
        c0 = hash_list[n-1]
        date = datetime.datetime.now()
        date = date.strftime("%Y-%m-%d")
        vendor_identity = 'Seller'

        hash_commit = SHA1.new()
        hash_commit.update(vendor_identity.encode())
        hash_commit.update(base64.b64encode(c_u))
        hash_commit.update(c0)
        hash_commit.update(date.encode())
        hash_commit.update(n)

        private_key_obj = RSA.import_key(keys[0])
        signer = PKCS1_v1_5.new(private_key_obj)
        signature = signer.sign(hash_commit)
        encrypted_signature = base64.b64encode(signature)

        commit_u = {
            'vendor_identity': vendor_identity,
            'c_u': c_u.decode('utf-8'),
            'c0': c0,
            'date': date,
            'info': n,
            'sign': encrypted_signature.decode('utf-8')
        }




