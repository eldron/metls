# to test metls handshake message size
# vary the number of middleboxes

import socket
from tlslite import TLSConnection
from tlslite.api import *
import sys
import ipaddress
import time
import random
import os

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print 'usage: ' + sys.argv[0] + ' server_ip server_port number_of_middleboxes'
    else:
        server_ip = sys.argv[1]
        server_port = int(sys.argv[2])
        number_of_middleboxes = int(sys.argv[3])
        cipher_suite = 'aes256gcm'
        curve_name = 'x25519'

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((server_ip, server_port))
        
        # now use sock to establish TLS 1.3 connection with the remote server
        connection = TLSConnection(sock)
        settings = HandshakeSettings()
        settings.cipherNames = [cipher_suite]
        settings.eccCurves = list([curve_name])
        settings.defaultCurve = curve_name
        settings.keyShares = [curve_name]

        settings.enable_metls = True
        settings.print_debug_info = True
        settings.calculate_ibe_keys = False
        settings.csibekey = bytearray(32)
        settings.c_to_s_mb_list = []
        settings.s_to_c_mb_list = []

        for i in range(number_of_middleboxes):
        	mbid = bytearray(os.urandom(64))
        	permission = bytearray(1)
        	permission[0] = random.randint(0, 1)
        	mb = {'middlebox_id':mbid, 'middlebox_permission':permission}
        	settings.s_to_c_mb_list.append(mb)

        connection.handshakeClientCert(settings=settings)

        handshake_msg_size = connection._recordLayer._recordSocket.data_sent + connection._recordLayer._recordSocket.data_received
        print 'handshake message size is: ' + str(handshake_msg_size) + ' bytes'
        
        connection.close()