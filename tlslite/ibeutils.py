from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair

# need to install Charm
# requires PKG to use symmetric mapping, i.e. (G1, G1)->G2

group = PairingGroup('SS512')
# master secret key
s = group.deserialize('0:RBthuauSAhEEpxuyKLh+jzsRYv0=')

def pairing_key_negotiation(id1, id2):
	public_key_1 = group.hash(id1, G1)
	public_key_2 = group.hash(id2, G1)
	private_key_1 = s * public_key_1
	key = pair(private_key_1, public_key_2)
	return group.serialize(key)