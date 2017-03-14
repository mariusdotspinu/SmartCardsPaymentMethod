import json
import socket
import base64

import cherrypy
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA1
from Crypto.Signature import PKCS1_v1_5


class Broker(object):
    def __init__(self):
        # generate RSA keys
        self.key = RSA.generate(2048)

        # initialise values
        self.pub_key_u = ''
        self.identity_u = ''
        self.ip_u = ''
        self.card_number = ''
        self.commit_u = {}
        self.payments_today = []
        self.credentials = {}

        fd = open("credentials.txt", "r")
        for line in fd:
            aux = line.split(" ")
            self.credentials[str(aux[0])] = [aux[1],aux[2][:-1]]

        fd.close()

    @cherrypy.expose
    def index(self):
        return "Broker Server"

    @cherrypy.expose
    def send_key(self):
        dict_key = {'Key_B': self.key.publickey().exportKey().decode("utf-8")}
        return json.dumps(dict_key)

    @cherrypy.expose
    def send_user_certificate(self):
        # get account information

        balance = self.credentials[self.card_number][0]
        exp_date = self.credentials[self.card_number][1]

        if self.pub_key_u == '' or self.identity_u == '' \
                or self.ip_u == '' or self.card_number == '':
            # something went wrong, return error
            return json.dumps({'error': "Invalid card number"})

        # build RSA signature over data
        hash_builder = SHA1.new()
        hash_builder.update("Broker".encode())
        hash_builder.update(self.identity_u.encode())
        hash_builder.update(self.ip_u.encode())
        hash_builder.update(self.key.publickey().exportKey())
        hash_builder.update(self.pub_key_u.encode())
        hash_builder.update(exp_date.encode())
        hash_builder.update(balance.encode())

        # encrypt hash with Broker's private key
        private_key_obj = RSA.import_key(self.key.exportKey())
        signer = PKCS1_v1_5.new(private_key_obj)
        signature = signer.sign(hash_builder)
        encrypted_signature = base64.b64encode(signature)

        # build certificate
        certificate = {
            'identity_B': "Broker",
            'identity_U': self.identity_u,
            'ip_U': self.ip_u,
            'key_B': self.key.publickey().exportKey().decode("utf-8"),
            'key_U': self.pub_key_u,
            'exp_date': exp_date,
            'balance': balance,
            'signature': encrypted_signature.decode("utf-8")
        }

        return json.dumps(certificate)

    @cherrypy.expose
    def receive_user_info(self, public_key_u='', identity_u='', ip_u='', card_number=''):
        self.pub_key_u = public_key_u
        self.identity_u = identity_u
        self.ip_u = ip_u
        self.card_number = card_number
        return 'OK'

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def redeem_vendor(self, commit_u, last_pay, last_pay_index):

        x = json.loads(commit_u)
        c_u = x["c_u"]
        sign = base64.b64decode(x["sign"])
        payment_chain = last_pay
        payment_value = last_pay_index
        payment_one = x["c0"]

        authentic = None

        rsa_key = RSA.importKey(self.pub_key_u)
        verifier = PKCS1_v1_5.new(rsa_key)

        # build hash commit u

        hash_builder_commit_u = SHA1.new()
        hash_builder_commit_u.update(x["c0"].encode())
        hash_builder_commit_u.update(json.dumps(x["c_u"]).encode())
        hash_builder_commit_u.update(x["date"].encode())
        hash_builder_commit_u.update(str(x["info"]).encode())
        hash_builder_commit_u.update(x["vendor_identity"].encode())

        if verifier.verify(hash_builder_commit_u, sign):
            authentic = "Ok"

        else:
            authentic = "Error"

        if c_u in self.payments_today:
            authentic = "Error"
        else:
            self.payments_today.append(c_u)

        if authentic == "Ok":

            for i in range(0, int(payment_value)):
                h_builder = SHA1.new()
                h_builder.update(str(payment_chain).encode())
                payment_chain = h_builder.hexdigest()

            if payment_chain == payment_one:
                print('All Ok')
                self.credentials[self.card_number][0] = str(int(self.credentials[self.card_number][0]) -
                                                            int(payment_value))


if __name__ == '__main__':
    cherrypy.server.socket_host = socket.gethostbyname(socket.gethostname())
    cherrypy.config.update({'server.socket_port': 60045})
    cherrypy.quickstart(Broker())
