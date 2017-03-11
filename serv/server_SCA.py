from Crypto.PublicKey import RSA
import cherrypy
import json
import socket
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
import simplejson


class StringGenerator(object):
    def __init__(self):
        self.key = RSA.generate(2048)
        self.pub_key_u = ''
        self.identity_u = ''
        self.ip_u = ''
        self.card_number = ''
        
    @cherrypy.expose
    def index(self):
        return "Broker Server"

    def get_serializable_keys(self):
        """Returns a tuple (private_key, public_key) as string objects encoded in
        UTF-8 format.
        """
        private_key = self.key.exportKey()
        private_key = private_key.decode("utf-8")

        public_key = self.key.publickey().exportKey()
        public_key = public_key.decode("utf-8")

        return private_key, public_key

    @cherrypy.expose
    def send_key(self):
        dict_key = {'Key_B': self.get_serializable_keys()[1]}
        return json.dumps(dict_key)

    @cherrypy.expose
    def send_sign_U(self):
        exp_date = None
        info = None
        with open('credentials.txt') as f:
            lines = f.readlines()
        for i in lines:
            if i[0] is self.card_number:
                exp_date = i[2]
                info = i[1]

        if self.pub_key_u == '' or self.identity_u == '' or self.ip_u == '' or self.card_number == '':
            return json.dumps({'ERROR': None})

        if exp_date == None:
            return json.dumps({'ERROR': None})

        identity_B = 'Broker'
        identity_U = self.identity_u
        ip_U = self.ip_u
        key_B = self.get_serializable_keys()[1]
        key_U = self.pub_key_u
        copy_plain_hash = identity_B
        copy_plain_hash += identity_U
        copy_plain_hash += ip_U
        copy_plain_hash += key_B
        copy_plain_hash += key_U
        copy_plain_hash += exp_date
        copy_plain_hash += info

        sig_hash = SHA256.new(copy_plain_hash.encode('utf-8'))

        signer = PKCS1_v1_5.new(self.key)

        sign = signer.sign(sig_hash)

        ret_dict = {'identity_B': identity_B, 'identity_U': identity_U, 'ip_U': ip_U, 'key_B': key_B, 'key_U': key_U,
                    'exp_date': exp_date, 'info': info, 'sig_hash': sign.decode('latin-1')}
        return json.dumps(ret_dict)

    @cherrypy.expose
    def recv_key(self, public_key_u='', identity_u='', ip_u='', card_number=''):
        self.pub_key_u = public_key_u
        self.identity_u = identity_u
        self.ip_u = ip_u
        self.card_number = card_number
        return 'OK'

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def redeem_V(self):

        input_json = cherrypy.request.json
        plain_message = input_json['message']
        sign = input_json['sig']
        payment_chain = input_json['ci']
        payment_value = input_json['i']
        payment_one = input_json['c0']

        authenthic = None

        rsa_key = RSA.importKey(self.pub_key_u)
        verifier = PKCS1_v1_5.new(rsa_key)
        h = SHA256.new(plain_message)

        if verifier.verify(h, sign):
            authenthic='Ok'
        else:
            authenthic='ERROR'

        sig_hash = SHA256.new(payment_chain.encode('utf-8'))

        for i in range(1, payment_value):
            sig_hash = SHA256.new(sig_hash.encode('utf-8'))

        if sig_hash==payment_one:
            print('All Ok')


if __name__ == '__main__':
    cherrypy.server.socket_host = socket.gethostbyname(socket.gethostname())
    cherrypy.quickstart(StringGenerator())
