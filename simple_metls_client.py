import socket
from tlslite import TLSConnection
from tlslite.api import *
import sys
import ipaddress
import time

if __name__ == '__main__':
    if len(sys.argv) != 5:
        print 'usage: ' + sys.argv[0] + ' server_ip server_port cipher_suite curve_name'
        print 'cipher_suite can be aes128gcm, aes256gcm or chacha20-poly1305'
        print 'curve_name can be x25519, x448, secp256r1, secp384r1 or secp521r1'
    else:
        server_ip = sys.argv[1]
        server_port = int(sys.argv[2])
        cipher_suite = sys.argv[3]
        curve_name = sys.argv[4]

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
        settings.client_server_key = bytearray(32)
        id1 = bytearray(64)
        id1[63] = 1
        id2 = bytearray(64)
        id2[63] = 2
        permission1 = bytearray(1)
        permission1[0] = 1
        permission2 = bytearray(1)
        permission2[0] = 1
        mb1 = {'middlebox_id':id1, 'middlebox_permission':permission1}
        mb2 = {'middlebox_id':id2, 'middlebox_permission':permission2}
        settings.c_to_s_mb_list = [mb1, mb2]
        settings.s_to_c_mb_list = [mb2, mb1]

        connection.handshakeClientCert(settings=settings)