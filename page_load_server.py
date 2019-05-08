# test metls https page load time
# vary the number of middleboxes on server to client path

import socket
import sys
from tlslite.api import *
import random
import os


if __name__ == '__main__':
	if len(sys.argv) != 3:
		print 'usage: ' + sys.argv[0] + ' ip port'
	else:
		private_key_file = "serverX509Key.pem"
		cert_file = "serverX509Cert.pem"
		s = open(private_key_file, "rb").read()
		if sys.version_info[0] >= 3:
			s = str(s, 'utf-8')
		# OpenSSL/m2crypto does not support RSASSA-PSS certificates
		privateKey = parsePEMKey(s, private=True, implementations=["python"])

		s = open(cert_file, "rb").read()
		if sys.version_info[0] >= 3:
			s = str(s, 'utf-8')
		x509 = X509()
		x509.parse(s)
		cert_chain = X509CertChain([x509])

		ip = sys.argv[1]
		port = int(sys.argv[2])

		settings = HandshakeSettings()
		settings.enable_metls = True
		settings.calculate_ibe_keys = False
		settings.csibekey = bytearray(32)
		settings.print_debug_info = False
		settings.c_to_s_mb_list = []
		settings.s_to_c_mb_list = []

		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.bind((ip, port))
		sock.listen(5)
		print 'server socket listening on ' + ip + ':' + str(port)
		while True:
			client_sock, client_addr = sock.accept()
			conn = TLSConnection(client_sock)
			print 'about to handshake'
			conn.handshakeServer(certChain=cert_chain, privateKey=privateKey, reqCert=False, settings=settings)
			print 'handshakeServer succeeded'

			# receive page request from client
			request = bytearray(conn.recv(3))
			amt = (request[0] << 16) | (request[1] << 8) | request[2]
			# transmit data to client
			conn.sendall(bytearray(amt))
			conn.close()
