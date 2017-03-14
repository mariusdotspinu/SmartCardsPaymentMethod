import json
import socket
import base64
import requests

import cherrypy
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA1
from Crypto.Signature import PKCS1_v1_5


def verify_received_info(commit):
    # get C(U)
    c_u = commit["c_u"]

    # build hash c_u
    hash_builder_c_u = SHA1.new()
    hash_builder_c_u.update(c_u["identity_B"].encode())
    hash_builder_c_u.update(c_u["identity_U"].encode())
    hash_builder_c_u.update(c_u["ip_U"].encode())
    hash_builder_c_u.update(c_u["key_B"].encode())
    hash_builder_c_u.update(c_u["key_U"].encode())
    hash_builder_c_u.update(c_u["exp_date"].encode())
    hash_builder_c_u.update(c_u["balance"].encode())

    # build hash commit_u
    hash_builder_commit_u = SHA1.new()
    hash_builder_commit_u.update(commit["c0"].encode())
    hash_builder_commit_u.update(json.dumps(commit["c_u"]).encode())
    hash_builder_commit_u.update(commit["date"].encode())
    hash_builder_commit_u.update(str(commit["info"]).encode())
    hash_builder_commit_u.update(commit["vendor_identity"].encode())

    # check signature from c_u
    signature_c_u_decoded = base64.b64decode(c_u["signature"])

    # check signature from commit_u

    signature_commit_u_decoded = base64.b64decode(commit["sign"])

    # get keys
    pub_key_b = RSA.import_key(c_u["key_B"].encode())
    pub_key_u = RSA.import_key(c_u["key_U"].encode())

    # set up verifiers
    verifier_c_u = PKCS1_v1_5.new(pub_key_b)
    verifier_commit_u = PKCS1_v1_5.new(pub_key_u)

    # if all is verified ,then authorized to make payments

    authenticated = False
    if verifier_c_u.verify(hash_builder_c_u, signature_c_u_decoded) and \
            verifier_commit_u.verify(hash_builder_commit_u, signature_commit_u_decoded):

        authenticated = True

    return authenticated


def construct_chain(index, c_index):
    index_temp = c_index.encode()

    for i in range(0, int(index)):
        h_builder = SHA1.new()
        h_builder.update(index_temp)
        index_temp = h_builder.hexdigest()
        index_temp = index_temp.encode()

    return index_temp.decode()


class Vendor(object):
    def __init__(self):
        self.u_authorized = False
        self.c0 = ""
        self.last_pay = ""
        self.last_pay_index = 0
        self.commit_u = {}

    @cherrypy.expose
    def index(self):
        return "Vendor Server"

    @cherrypy.expose
    def check_commit(self, commit_v):
        x = json.loads(commit_v)
        self.commit_u = x
        self.c0 = x["c0"]
        print("Received commit(U) :" + json.dumps(x, sort_keys=True, indent=4))
        self.u_authorized = verify_received_info(x)
        return

    @cherrypy.expose
    def check_if_u_is_authorized_to_make_payments(self):
        if self.u_authorized:
            return "True"
        return "False"

    @cherrypy.expose
    def verify_payment_authenticity(self, pay, index):
        print(construct_chain(index, pay), "c0", self.c0)
        if construct_chain(index, pay) == self.c0:
            print("Accepted " + index + ": payment")
            self.last_pay = pay
            self.last_pay_index = index
        else:
            print("Rejected " + index + " : payment")

    @cherrypy.expose
    def end_day(self):
        requests.get("http://192.168.0.10:60045/redeem_vendor", params={
            "commit_u": json.dumps(self.commit_u),
            "last_pay": self.last_pay,
            "last_pay_index": self.last_pay_index
        })

        print("Vendor sent commit (U) to broker and payment info")


if __name__ == '__main__':
    cherrypy.server.socket_host = socket.gethostbyname(socket.gethostname())
    cherrypy.config.update({'server.socket_port': 30045})
    cherrypy.quickstart(Vendor())