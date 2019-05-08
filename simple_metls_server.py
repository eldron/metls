import socket
import sys
from tlslite.api import *
import random
import os


if __name__ == '__main__':
	if len(sys.argv) != 4:
		print 'usage: ' + sys.argv[0] + ' ip port number_of_middleboxes'
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
		number_of_middleboxes = int(sys.argv[3])

		settings = HandshakeSettings()
		settings.enable_metls = True
		settings.calculate_ibe_keys = False
		settings.csibekey = bytearray(32)
		settings.print_debug_info = True
		settings.c_to_s_mb_list = []
		settings.s_to_c_mb_list = []
		# server introduce client to server middleboxes
		for i in range(number_of_middleboxes):
			mbid = bytearray(os.urandom(64))
			permission = bytearray(1)
			permission[0] = random.randint(0, 1)
			mb = {'middlebox_id':mbid, 'middlebox_permission':permission}
			settings.c_to_s_mb_list.append(mb)

		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.bind((ip, port))
		sock.listen(5)
		print 'server socket listening on ' + ip + ':' + str(port)
		client_sock, client_addr = sock.accept()
		conn = TLSConnection(client_sock)
		print 'about to handshake'
		conn.handshakeServer(certChain=cert_chain, privateKey=privateKey, reqCert=False, settings=settings)
		print 'handshakeServer succeeded'

		handshake_msg_size = conn._recordLayer._recordSocket.data_sent + conn._recordLayer._recordSocket.data_received
		print 'handshake message size is: ' + str(handshake_msg_size) + ' bytes'

		# test data transfer
		count = 0
		while True:
			data = conn.recv(20000)
			if len(data) > 0:
				count += len(data)
				print 'received ' + str(count) + ' bytes data'
				conn.sendall(data)
			else:
				break
		# while True:
		# 	while True:
		# 		request = conn.recv(2000)
		# 		if isinstance(request, str):
		# 			break
		# 	#conn.sendall("tls test delay response")
		# 	conn.sendall(bytearray(content_size))
