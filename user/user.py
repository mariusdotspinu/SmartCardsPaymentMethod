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
    hash_chain = list()

    secret = generate_secret()
    hash_chain.append(secret)

    for i in range(0, n):
        h_builder = SHA1.new()
        h_builder.update(str(secret).encode())
        secret = h_builder.hexdigest()
        hash_chain.append(secret)

    return hash_chain


if __name__ == "__main__":
    # generate keys

    # get ip
    ip = socket.gethostbyname(socket.gethostname())
    ip_vendor = "http://127.0.0.1:30045"
    ip_broker = "http://127.0.0.1:60045"

    # call receive_user_info
    url = ip_broker + "/receive_user_info"
    keys = generate_rsa_keys(2048)
    c_u = requests.get(url, params={
        "public_key_u": keys[1],
        "identity_u": "USER",
        "ip_u": ip,
        "card_number": "1111-1111-1111-1111"
    })
    print("Sent user info to Broker")

    # call send_user_certificate
    url = ip_broker + "/send_user_certificate"
    c_u = json.loads(requests.get(url).text)

    print("Received certificate from Broker: ")
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
        print("Authorized for chain hash")
        number = 100
        hash_list = generate_hash_chain(number)
        c0 = hash_list[-1]
        date = datetime.datetime.now()
        date = date.strftime("%Y-%m-%d")
        vendor_identity = 'Seller'

        hash_commit = SHA1.new()
        hash_commit.update(str(c0).encode())
        hash_commit.update(json.dumps(c_u).encode())
        hash_commit.update(date.encode())
        hash_commit.update(str(number).encode())
        hash_commit.update(vendor_identity.encode())

        private_key_obj = RSA.import_key(keys[0])
        signer = PKCS1_v1_5.new(private_key_obj)
        signature = signer.sign(hash_commit)
        encrypted_signature = base64.b64encode(signature)

        commit_u = {
            'vendor_identity': vendor_identity,
            'c_u': c_u,
            'c0': c0,
            'date': date,
            'info': number,
            'sign': encrypted_signature.decode('utf-8')
        }

        # call check_commit from vendor

        url = ip_vendor + "/check_commit"
        requests.get(url, params={
            "commit_v": json.dumps(commit_u)})

        print("Commit(U) sent to vendor")

        # check if user is authorized to make payments
        authorized_payments = requests.get(ip_vendor + "/check_if_u_is_authorized_to_make_payments").text
        print("Authorized is " + authorized_payments)

        if authorized_payments == "True":
            limit = 0
            while 1:
                choice = input("Insert 1 for another payment or 2 for the same, 3 for redeem, 4 multiple payments")

                if choice == "1":
                    requests.get(ip_vendor + "/verify_payment_authenticity", params={
                        "pay": hash_list[-2-limit],  # c0 e la capatul listei, deci -2
                        "index": limit + 1
                    })

                    limit += 1

                elif choice == "2":
                    requests.get(ip_vendor + "/verify_payment_authenticity", params={
                        "pay": hash_list[-2-limit],
                        "index": limit
                    })
                elif choice == "3":
                    print("Send end day status to vendor")
                    requests.get(ip_vendor + "/end_day")
                    break
                elif choice == "4":
                    nr_payments = input("Insert how many : ")

                    requests.get(ip_vendor + "/verify_payment_authenticity", params={
                        "pay": hash_list[-1-int(nr_payments) - limit],  # c0 e la capatul listei, deci -2
                        "index": limit + int(nr_payments)
                    })
                    limit += int(nr_payments)