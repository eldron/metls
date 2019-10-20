from tlslite.utils.cryptomath import *
import time
from tlslite.utils import pycrypto_aesgcm
from tlslite.tlsconnection import *
from tlslite.api import *

authdata = bytearray(6)
nonce = bytearray(12)

times = 10000
k = bytearray(32)
a = bytearray(32)
label = bytearray(b'derived')

aesgcm = pycrypto_aesgcm.new(k)
plaintext = bytearray(512)
ciphertext = bytearray(144)

print 'testing secureHMAC sha256'
time1 = time.time()
for i in range(times):
	result = secureHMAC(k, a, 'sha256')
time2 = time.time()
result = (time2 * 1000 - time1 * 1000) / times
print 'sha256 HMAC is ' + str(result) + ' milisecond'

print 'testing secureHMAC sha384'
time1 = time.time()
for i in range(times):
	result = secureHMAC(k, a, 'sha384')
time2 = time.time()
result = (time2 * 1000 - time1 * 1000) / times
print 'sha256 HMAC is ' + str(result) + ' milisecond'

print 'testing derive secret sha256'
time1 = time.time()
for i in range(times):
	result = derive_secret(k, label, None, 'sha256')
time2 = time.time()
result = (time2 * 1000 - time1 * 1000) / times
print 'sha256 derive secret is ' + str(result) + ' milisecond'

print 'testing derive secret sha384'
time1 = time.time()
for i in range(times):
	result = derive_secret(k, label, None, 'sha384')
time2 = time.time()
result = (time2 * 1000 - time1 * 1000) / times
print 'sha384 derive secret is ' + str(result) + ' milisecond'

print 'testing HKDF-expand-label sha256'
time1 = time.time()
for i in range(times):
	result = HKDF_expand_label(k, b"finished", b'', 32, 'sha256')
time2 = time.time()
result = (time2 * 1000 - time1 * 1000) / times
print 'HKDF expand label sha256 is ' + str(result) + ' milisecond'

print 'testing HKDF-expand-label sha384'
time1 = time.time()
for i in range(times):
	result = HKDF_expand_label(k, b"finished", b'', 32, 'sha384')
time2 = time.time()
result = (time2 * 1000 - time1 * 1000) / times
print 'HKDF expand label sha384 is ' + str(result) + ' milisecond'

print 'testing aesgcm seal'
time1 = time.time()
for i in range(times):
	ciphertext = aesgcm.seal(nonce, plaintext, authdata)
time2 = time.time()
result = (time2 * 1000 - time1 * 1000) / times
print 'aesgcm seal takes ' + str(result) + ' milisecond'

print 'testing aesgcm open'
time1 = time.time()
for i in range(times):
	plaintext = aesgcm.open(nonce, ciphertext, authdata)
time2 = time.time()
result = (time2 * 1000 - time1 * 1000) / times
print 'aesgcm open takes ' + str(result) + ' milisecond'


print 'testing ecc exponential'
kex = ECDHKeyExchange(GroupName.x25519, (3, 3))
time1 = time.time()
private = None
public = None
for i in range(times):
	private = kex.get_random_private_key()
time2 = time.time()
result = (time2 * 1000 - time1 * 1000) / times
print 'ecc get_random_private_key ' + str(result) + ' milisecond'

time1 = time.time()
for i in range(times):
	public = kex.calc_public_value(private)
time2 = time.time()
result = (time2 * 1000 - time1 * 1000) / times
print 'ecc calc_public_value ' + str(result) + ' milisecond'

time1 = time.time()
for i in range(times):
	kex.calc_shared_key(private, public)
time2 = time.time()
result = (time2 * 1000 - time1 * 1000) / times
print 'ecc calc_shared_key ' + str(result) + ' milisecond'

print 'testing rsa signatrue generation time'
private_key_file = "serverX509Key.pem"
s = open(private_key_file, "rb").read()
privateKey = parsePEMKey(s, private=True, implementations=["python"])
data = bytearray(32)
sig = None
time1 = time.time()
for i in range(times):
	sig = privateKey.sign(data)
time2 = time.time()
result = (time2 * 1000 - time1 * 1000) / times
print 'rsa signatrue generation time is ' + str(result) + ' milisecond'

print 'testing rsa signatrue verification time'
time1 = time.time()
for i in range(times):
	privateKey.verify(sig, data)
time2 = time.time()
result = (time2 * 1000 - time1 * 1000) / times
print 'rsa signatrue verification time is ' + str(result) + ' milisecond'
