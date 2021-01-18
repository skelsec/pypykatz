
from asn1crypto import core
from minikerberos.protocol.asn1_structs import krb5int32, APOptions, Ticket, EncryptedData, AP_REQ

UNIVERSAL = 0
APPLICATION = 1
CONTEXT = 2
TAG = 'explicit'

class MechType(core.ObjectIdentifier):
	_map = { 
		#'': 'SNMPv2-SMI::enterprises.311.2.2.30',
		'1.3.6.1.4.1.311.2.2.10': 'NTLMSSP - Microsoft NTLM Security Support Provider',
		'1.2.840.48018.1.2.2'   : 'MS KRB5 - Microsoft Kerberos 5',
		'1.2.840.113554.1.2.2'  : 'KRB5 - Kerberos 5',
		'1.2.840.113554.1.2.2.3': 'KRB5 - Kerberos 5 - User to User',
		'1.3.6.1.4.1.311.2.2.30': 'NEGOEX - SPNEGO Extended Negotiation Security Mechanism',
	}

class InitialContextToken(core.Sequence):	
	class_ = 1
	tag    = 0
	_fields = [
		('thisMech', MechType, {'optional': False}),
		('unk_bool', core.Boolean, {'optional': False}),
		('innerContextToken', core.Any, {'optional': False}),
	]

	_oid_pair = ('thisMech', 'innerContextToken')
	_oid_specs = {
		'KRB5 - Kerberos 5': AP_REQ,
}