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
        balance = None
        exp_date = None
        try:
            fd = open("credentials.txt", "r")
            for line in fd:
                aux = line.split(" ")
                if aux[0] == self.card_number:
                    # found card number, load information
                    balance = aux[1]
                    exp_date = aux[2][:-1]
                    break
            fd.close()
        except IOError as e:
            return json.dumps({
                "error": "Could not open credentials.txt",
                "Exception": e
            })

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

        # TODO: cripteaza JSONUL
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
    def redeem_vendor(self):
        # TODO: fix this (not working atm)
        input_json = cherrypy.request.json
        plain_message = input_json['message']
        sign = input_json['sig']
        payment_chain = input_json['ci']
        payment_value = input_json['i']
        payment_one = input_json['c0']

        authentic = None

        rsa_key = RSA.importKey(self.pub_key_u)
        verifier = PKCS1_v1_5.new(rsa_key)
        h = SHA256.new(plain_message)

        if verifier.verify(h, sign):
            authentic = 'Ok'
        else:
            authentic = 'ERROR'

        sig_hash = SHA256.new(payment_chain.encode('utf-8'))

        for i in range(1, payment_value):
            sig_hash = SHA256.new(sig_hash.encode('utf-8'))

        if sig_hash == payment_one:
            print('All Ok')


if __name__ == '__main__':
    cherrypy.server.socket_host = socket.gethostbyname(socket.gethostname())
    cherrypy.config.update({'server.socket_port': 60045})
    cherrypy.quickstart(Broker())
