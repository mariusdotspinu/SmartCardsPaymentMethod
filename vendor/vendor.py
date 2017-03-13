import json
import socket
import base64

import cherrypy
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA1
from Crypto.Signature import PKCS1_v1_5


class Vendor(object):
    def __init__(self):
        self.user_commit = {}

    @cherrypy.expose
    def index(self):
        return "Vendor Server"

    @cherrypy.expose
    def check_commit(self):
        print("intra")
        return


if __name__ == '__main__':
    cherrypy.server.socket_host = socket.gethostbyname(socket.gethostname())
    cherrypy.config.update({'server.socket_port': 30045})
    cherrypy.quickstart(Vendor())