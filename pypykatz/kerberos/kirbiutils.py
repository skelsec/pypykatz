

from minikerberos.protocol.asn1_structs import KRB_CRED, EncKrbCredPart, KRBCRED
import base64

def format_kirbi(data, n = 100):
	kd = base64.b64encode(data).decode()
	return '    ' + '\r\n    '.join([kd[i:i+n] for i in range(0, len(kd), n)])

def describe_kirbi_data(data):
	if isinstance(data, bytes):
		kirbi = KRB_CRED.load(data).native
	elif isinstance(data, dict):
		kirbi = data
	elif isinstance(data, KRB_CRED):
		kirbi = data.native
	elif isinstance(data, KRBCRED):
		kirbi = data.native
	else:
		raise Exception('Unknown data type! %s' % type(data))
	
	t = '\r\n'
	for ticket in kirbi['tickets']:
		t += 'Realm        : %s\r\n' % ticket['realm']
		t += 'Sname        : %s\r\n' % '/'.join(ticket['sname']['name-string'])

	if kirbi['enc-part']['etype'] == 0:
		cred = EncKrbCredPart.load(kirbi['enc-part']['cipher']).native
		cred = cred['ticket-info'][0]
		username = cred.get('pname')
		if username is not None:
			username = '/'.join(username['name-string'])
		flags = cred.get('flags')
		if flags is not None:
			flags = ', '.join(flags)

		t += 'UserName     : %s\r\n' % username
		t += 'UserRealm    : %s\r\n' % cred.get('prealm')
		t += 'StartTime    : %s\r\n' % cred.get('starttime')
		t += 'EndTime      : %s\r\n' % cred.get('endtime')
		t += 'RenewTill    : %s\r\n' % cred.get('renew-till')
		t += 'Flags        : %s\r\n' % flags
		t += 'Keytype      : %s\r\n' % cred['key']['keytype']
		t += 'Key          : %s\r\n' % base64.b64encode(cred['key']['keyvalue']).decode()

	t += 'EncodedKirbi : \r\n\r\n'
	t += format_kirbi(KRB_CRED(kirbi).dump())
	return t

def print_kirbi(data):
	print(describe_kirbi_data(data))



def parse_kirbi(kirbifile):
	with open(kirbifile, 'rb') as f:
		print_kirbi(f.read())