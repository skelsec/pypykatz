from asn1crypto import core
from pypykatz.commons.filetime import *
from pypykatz.commons.common import *
import enum
import os

# KerberosV5Spec2 DEFINITIONS EXPLICIT TAGS ::=
TAG = 'explicit'

# class
APPLICATION = 1

# strict parsing w/o trailing bytes
STRICT = True


class Microseconds(core.Integer):
	"""    ::= INTEGER (0..999999)
	-- microseconds
    """      
class Int32(core.Integer):
    """Int32 ::= INTEGER (-2147483648..2147483647)
    """


class UInt32(core.Integer):
    """UInt32 ::= INTEGER (0..4294967295)
    """

class KerberosString(core.GeneralString):
	"""KerberosString ::= GeneralString (IA5String)
	For compatibility, implementations MAY choose to accept GeneralString
	values that contain characters other than those permitted by
	IA5String...
	"""
	
class HostAddress(core.Sequence):
    """HostAddress for HostAddresses
    HostAddress ::= SEQUENCE {
        addr-type        [0] Int32,
        address  [1] OCTET STRING
    }
    """
    _fields = [
        ('addr-type', Int32, {'tag_type': TAG, 'tag': 0}),
        ('address', core.OctetString, {'tag_type': TAG, 'tag': 1}),
]

class SequenceOfHostAddress(core.SequenceOf):
	"""SEQUENCE OF HostAddress
	"""
	_child_spec = HostAddress
	
class SequenceOfKerberosString(core.SequenceOf):
	"""SEQUENCE OF KerberosString
	"""
	_child_spec = KerberosString

# https://github.com/tiran/kkdcpasn1/blob/asn1crypto/pykkdcpasn1.py
class Realm(KerberosString):
	"""Realm ::= KerberosString
	"""

# https://github.com/tiran/kkdcpasn1/blob/asn1crypto/pykkdcpasn1.py
class PrincipalName(core.Sequence):
	"""PrincipalName for KDC-REQ-BODY and Ticket
	PrincipalName ::= SEQUENCE {
		name-type	[0] Int32,
		name-string  [1] SEQUENCE OF KerberosString
	}
	"""
	_fields = [
		('name-type', Int32, {'tag_type': TAG, 'tag': 0}),
		('name-string', SequenceOfKerberosString, {'tag_type': TAG, 'tag': 1}),
]

# https://github.com/tiran/kkdcpasn1/blob/asn1crypto/pykkdcpasn1.py
class EncryptedData(core.Sequence):
	"""EncryptedData
	* KDC-REQ-BODY
	* Ticket
	* AP-REQ
	* KRB-PRIV
	EncryptedData ::= SEQUENCE {
		etype		[0] Int32,
		kvno		 [1] UInt32 OPTIONAL,
		cipher	   [2] OCTET STRING
	}
	"""
	_fields = [
		('etype', Int32, {'tag_type': TAG, 'tag': 0}),
		('kvno', UInt32, {'tag_type': TAG, 'tag': 1, 'optional': True}),
		('cipher', core.OctetString, {'tag_type': TAG, 'tag': 2}),
]

class EncryptionKey(core.Sequence):
	"""
	EncryptionKey ::= SEQUENCE {
	keytype[0]		krb5int32,
	keyvalue[1]		OCTET STRING
	}
	"""
	_fields = [
		('keytype', Int32, {'tag_type': TAG, 'tag': 0}),
		('keyvalue', core.OctetString, {'tag_type': TAG, 'tag': 1}),
]

# https://github.com/tiran/kkdcpasn1/blob/asn1crypto/pykkdcpasn1.py
class Ticket(core.Sequence):
	"""Ticket for AP-REQ and SEQUENCE OF Ticket

	Ticket ::= [APPLICATION 1] SEQUENCE {
		tkt-vno	  [0] INTEGER,
		realm		[1] Realm,
		sname		[2] PrincipalName,
		enc-part	 [3] EncryptedData
	}
	"""
	#explicit_class = APPLICATION
	#explicit_tag = 1
	#tag_type = TAG
	#explicit = (1, 1)
	explicit = (1,1)
	
	_fields = [
		('tkt-vno', core.Integer, {'tag_type': TAG, 'tag': 0}),
		('realm', Realm, {'tag_type': TAG, 'tag': 1}),
		('sname', PrincipalName, {'tag_type': TAG, 'tag': 2}),
		('enc-part', EncryptedData, {'tag_type': TAG, 'tag': 3}),
	]
	

class TicketFlags(core.BitString):
	"""
	TicketFlags ::= BIT STRING {
	reserved(0),
	forwardable(1),
	forwarded(2),
	proxiable(3),
	proxy(4),
	may-postdate(5),
	postdated(6),
	invalid(7),
	renewable(8),
	initial(9),
	pre-authent(10),
	hw-authent(11),
	transited-policy-checked(12),
	ok-as-delegate(13),
	anonymous(14),
	enc-pa-rep(15)
	}
	"""
	_map = {
		0: 'reserved',
		1: 'forwardable',
		2: 'forwarded',
		3: 'proxiable',
		4: 'proxy',
		5: 'may-postdate',
		6: 'postdated',
		7: 'invalid',
		8: 'renewable',
		9: 'initial',
		10: 'pre_authent',
		11: 'hw_authent',
		12: 'transited_policy_checked',
		13: 'ok_as_delegate',
		14: 'anonymous',
		15: 'enc_pa_rep',
	}
	

class KerberosTicketFlags(enum.IntFlag):
	reserved = 1
	forwardable = 2
	forwarded = 4
	proxiable = 8
	proxy = 16
	may_postdate = 32
	postdated = 64
	invalid = 128
	renewable = 256
	initial = 512
	pre_authent = 1024
	hw_authent = 2048
	transited_policy_checked = 4096
	ok_as_delegate = 8192
	anonymous = 16384
	enc_pa_rep = 32768


class KerberosTime(core.GeneralizedTime):
    """KerberosTime ::= GeneralizedTime
    """


class SequenceOfTicket(core.SequenceOf):
	"""SEQUENCE OF Ticket for KDC-REQ-BODY
	"""
	_child_spec = Ticket


class SequenceOfInt32(core.SequenceOf):
	"""SEQUENCE OF Int32 for KDC-REQ-BODY
	"""
	_child_spec = Int32

# http://web.mit.edu/freebsd/head/crypto/heimdal/lib/asn1/krb5.asn1
class KrbCredInfo(core.Sequence):
	_fields = [
		('key', EncryptionKey, {'tag_type': TAG, 'tag': 0}),
		('prealm', Realm, {'tag_type': TAG, 'tag': 1, 'optional': True}),
		('pname', PrincipalName, {'tag_type': TAG, 'tag': 2, 'optional': True}),
		('flags', TicketFlags , {'tag_type': TAG, 'tag': 3, 'optional': True}),
		('authtime', KerberosTime , {'tag_type': TAG, 'tag': 4, 'optional': True}),
		('starttime', KerberosTime , {'tag_type': TAG, 'tag': 5, 'optional': True}),
		('endtime', KerberosTime , {'tag_type': TAG, 'tag': 6, 'optional': True}),
		('renew-till', KerberosTime , {'tag_type': TAG, 'tag': 7, 'optional': True}),
		('srealm', Realm , {'tag_type': TAG, 'tag': 8, 'optional': True}),
		('sname', PrincipalName , {'tag_type': TAG, 'tag': 9, 'optional': True}),
		('caddr', SequenceOfHostAddress , {'tag_type': TAG, 'tag': 10, 'optional': True}),
	]
	
class SequenceOfKrbCredInfo(core.SequenceOf):
	_child_spec = KrbCredInfo
	
	
class EncKrbCredPart(core.Sequence):
	explicit = (1, 29)
	
	_fields = [
		('ticket-info', SequenceOfKrbCredInfo, {'tag_type': TAG, 'tag': 0}),
		('nonce', Int32, {'tag_type': TAG, 'tag': 1, 'optional': True}),
		('timestamp', KerberosTime , {'tag_type': TAG, 'tag': 2, 'optional': True}),
		('usec', Microseconds , {'tag_type': TAG, 'tag': 3, 'optional': True}),
		('s-address', HostAddress , {'tag_type': TAG, 'tag': 4, 'optional': True}),
		('r-address', HostAddress , {'tag_type': TAG, 'tag': 5, 'optional': True}),
	]
	
class KRBCRED(core.Sequence):
	#explicit_class = APPLICATION
	#explicit_tag = 22
	#tag_type = TAG
	#explicit = (TAG, 22)
	#explicit = (22, 1)
	explicit = (1, 22)
	#class_ = 1
	#tag = 22
	#tag_type = TAG
	
	
	_fields = [
		('pvno', core.Integer, {'tag_type': TAG, 'tag': 0}),
		('msg-type', core.Integer, {'tag_type': TAG, 'tag': 1}),
		('tickets', SequenceOfTicket, {'tag_type': TAG, 'tag': 2}),
		('enc-part', EncryptedData , {'tag_type': TAG, 'tag': 3}),
	
	]
	
class KerberosEncryptonType(enum.Enum):
	#KERB_ETYPE_
	NULL = 0
	DES_CBC_CRC = 1
	DES_CBC_MD4 = 2
	DES_CBC_MD5 = 3
	
	RC4_MD4 = -128
	RC4_PLAIN2 = -129
	RC4_LM = -130
	RC4_SHA = -131
	DES_PLAIN = -132
	RC4_HMAC_OLD = -133
	RC4_PLAIN_OLD = -134
	RC4_HMAC_OLD_EXP = -135
	RC4_PLAIN_OLD_EXP = -136
	RC4_PLAIN = -140
	RC4_PLAIN_EXP = -141
	
	""" WTF is repeating values???
	DSA_SHA1_CMS = 9
	RSA_MD5_CMS = 10
	RSA_SHA1_CMS = 11
	RC2_CBC_ENV = 12
	RSA_ENV = 13
	RSA_ES_OEAP_ENV = 14
	DES_EDE3_CBC_ENV = 15
	
	DSA_SIGN = 8
	RSA_PRIV = 9
	RSA_PUB =  10
	RSA_PUB_MD5 = 11
	RSA_PUB_SHA1 = 12
	PKCS7_PUB = 13
	"""
	DES3_CBC_MD5 =  5
	DES3_CBC_SHA1 = 7
	DES3_CBC_SHA1_KD = 16
	
	DES_CBC_MD5_NT = 20
	RC4_HMAC_NT = 23
	RC4_HMAC_NT_EXP = 24
	
	
class KerberosTicket:
	def __init__(self):
		self.ServiceName = None
		self.ServiceName_type = None
		self.DomainName = None
		self.ETargetName = None
		self.ETargetName_type = None
		self.TargetDomainName = None
		self.EClientName = None
		self.EClientName_type = None
		self.AltTargetDomainName = None
		self.Description = None

		self.StartTime = None
		self.EndTime = None
		self.RenewUntil = None

		self.KeyType = None
		self.Key = None

		self.TicketFlags = None
		self.TicketEncType = None
		self.TicketKvno = None
		self.Ticket = None
		
	def to_asn1(self):
		#this will in fact return a KRBCRED object, not a Ticket object!!!
		krbcred = {}
		krb = {}
		ticket = {}
		tickets = SequenceOfTicket()
		
		#encpart
		encpart = {}
		encpart['etype']  = self.TicketEncType
		encpart['kvno']   =  self.TicketKvno
		encpart['cipher'] = self.Ticket
		ticket['enc-part'] = EncryptedData(encpart)
		
		#sname
		sname = {}
		sname['name-type'] = self.ServiceName_type
		t = SequenceOfKerberosString()
		for s in self.ServiceName:
			a = KerberosString(s)
			t.append(a)
		sname['name-string'] = SequenceOfKerberosString(t)
		ticket['sname'] = PrincipalName(sname)
		
		#realm
		realm = Realm(self.DomainName)
		ticket['realm'] = realm
		
		#vno
		ticket['tkt-vno'] = self.TicketKvno #check this, not sure if this is correct!!!!
		tickets.append(Ticket(ticket))
		
		############# krb
		key = {}
		key['keytype'] = self.KeyType
		key['keyvalue'] = self.Key
		krb['key'] = EncryptionKey(key)
		
		prealm = Realm(self.AltTargetDomainName)
		krb['prealm'] = prealm
		
		pname = {}
		pname['name-type'] = self.EClientName_type
		pname['name-string'] = self.EClientName
		krb['pname'] = PrincipalName(pname)
		
		flags = tuple([self.TicketFlags >> i & 1 for i in range(self.TicketFlags.bit_length() - 1,-1,-1)])
		krb['flags'] = TicketFlags(flags)
		
		krb['starttime'] = KerberosTime(self.StartTime)
		krb['endtime'] = KerberosTime(self.EndTime)
		krb['renew-till'] = KerberosTime(self.RenewUntil)		
		
		srealm = Realm(self.DomainName)
		krb['srealm'] = srealm
		
		sname = {}
		sname['name-type'] = self.ServiceName_type
		sname['name-string'] = self.ServiceName
		krb['sname'] = PrincipalName(sname)
		
		krb = KrbCredInfo(krb)
		with open('new.asn1','wb') as f:
			f.write(krb.dump())
		
		krbcred['pvno'] = 5
		krbcred['msg-type'] = 22
		krbcred['tickets'] = tickets
		
		r = SequenceOfKrbCredInfo()
		r.append(krb)
		
		enckrbcredpart = {}
		enckrbcredpart['ticket-info'] = r 
		
		with open('new2.asn1','wb') as f:
			f.write(r.dump())
		
		encpart = {}
		encpart['etype']  = KerberosEncryptonType.NULL.value
		encpart['cipher'] = EncKrbCredPart(enckrbcredpart).dump()
		
		
		encpart = EncryptedData(encpart)
		
		with open('new2.asn1','wb') as f:
			f.write(EncKrbCredPart(enckrbcredpart).dump())
		
		
		krbcred['enc-part'] = encpart
		
		input('ENCPART: \n%s' % hexdump(encpart.dump()))
		
		return KRBCRED(krbcred)
		
		
	def parse(kerberos_ticket, reader):
		kt = KerberosTicket()
		kt.ServiceName_type = kerberos_ticket.ServiceName.read(reader).NameType
		kt.ServiceName = kerberos_ticket.ServiceName.read(reader).read(reader)
		kt.DomainName = kerberos_ticket.DomainName.read_string(reader)
		kt.ETargetName = kerberos_ticket.TargetName.read(reader).read(reader)
		kt.ETargetName_type = kerberos_ticket.TargetName.read(reader).NameType 
		kt.TargetDomainName = kerberos_ticket.TargetDomainName.read_string(reader) 
		kt.EClientName = kerberos_ticket.ClientName.read(reader).read(reader)
		kt.EClientName_type = kerberos_ticket.ClientName.read(reader).NameType
		kt.AltTargetDomainName = kerberos_ticket.AltTargetDomainName.read_string(reader)
		kt.Description = kerberos_ticket.Description.read_string(reader)
		
		kt.StartTime = filetime_to_dt(kerberos_ticket.StartTime)
		kt.EndTime = filetime_to_dt(kerberos_ticket.StartTime)
		kt.RenewUntil = filetime_to_dt(kerberos_ticket.StartTime)
		
		kt.KeyType = kerberos_ticket.KeyType
		kt.Key = kerberos_ticket.Key.read(reader)
		
		kt.TicketFlags = KerberosTicketFlags(kerberos_ticket.TicketFlags >> 15)
		kt.TicketEncType = kerberos_ticket.TicketEncType
		kt.TicketKvno = kerberos_ticket.TicketKvno
		kt.Ticket = kerberos_ticket.Ticket.read(reader)
		
		print(hexdump(kt.Ticket))
		with open('%s.kirbi' % os.urandom(4).hex(), 'wb') as f:
			f.write(kt.to_asn1().dump())
		#print(kt.to_asn1().native)
		#input('like ticket?')
		
		return kt
	
	def __str__(self):
		t =  '== Kerberos Ticket ==\n'
		t += 'ServiceName: %s\n'% self.ServiceName
		t += 'DomainName: %s\n'% self.DomainName
		t += 'ETargetName: %s\n'% self.ETargetName
		t += 'TargetDomainName: %s\n'% self.TargetDomainName
		t += 'EClientName: %s\n'% self.EClientName
		t += 'AltTargetDomainName: %s\n'% self.AltTargetDomainName
		t += 'Description: %s\n'% self.Description
		t += 'StartTime: %s\n'% self.StartTime.isoformat()
		t += 'EndTime: %s\n'% self.EndTime.isoformat()
		t += 'RenewUntil: %s\n'% self.RenewUntil.isoformat()
		t += 'KeyType: %s\n'% self.KeyType
		t += 'Key: %s\n'% self.Key
		t += 'TicketFlags: %s\n'% self.TicketFlags
		t += 'TicketEncType: %s\n'% self.TicketEncType
		t += 'TicketKvno: %s\n'% self.TicketKvno
		t += 'Ticket: %s\n'% self.Ticket.hex()		
		return t
		