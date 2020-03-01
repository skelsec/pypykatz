#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import datetime
from asn1crypto import core
from pypykatz.commons.filetime import filetime_to_dt
from pypykatz.commons.common import WindowsBuild, GenericReader
from pypykatz.commons.win_datatypes import LSAISO_DATA_BLOB, ENC_LSAISO_DATA_BLOB
from minikerberos.protocol.asn1_structs import EncryptionKey, PrincipalName, \
	TicketFlags, KrbCredInfo, krb5_pvno, EncryptedData, KRBCRED, Ticket, \
	EncKrbCredPart
from minikerberos.protocol.constants import NAME_TYPE, MESSAGE_TYPE, EncryptionType

import enum
import os
import hashlib

class KerberosTicketType(enum.Enum):
	TGT = enum.auto()
	TGS = enum.auto()
	CLIENT = enum.auto() #?
	
class KerberosSessionKey:
	def __init__(self):
		self.keydata = None
		self.sessionkey = None
	
	@staticmethod
	def parse(key_struct, sysinfo):
		ksk = KerberosSessionKey()
		ksk.keydata = key_struct.Data
		
		if sysinfo.buildnumber < WindowsBuild.WIN_10_1507.value or key_struct.Length < LSAISO_DATA_BLOB.size:
			ksk.sessionkey = ksk.keydata
		else:
			reader = GenericReader(ksk.keydata, processor_architecture = sysinfo.architecture)
			if key_struct.Length <= (LSAISO_DATA_BLOB.size + len("KerberosKey")-1 + 32) :
				blob = LSAISO_DATA_BLOB(reader)
				blob.Data = reader.read(-1)
			else:
				blob = ENC_LSAISO_DATA_BLOB(reader)
				blob.Data = reader.read(-1)
			
			ksk.sessionkey = blob.Data
		return ksk
	
class KerberosTicket:
	def __init__(self):
		self.type = None
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
		
		self.kirbi_data = {}
		self.session_key = None
		
	#def generate_filename(self):
	#	return '%s@%s_%s' % ('-'.join(self.EClientName) , '-'.join(self.ServiceName), hashlib.sha1(self.Ticket).hexdigest()[:8])
	
	def to_dict(self):
		#not sure if anyone would need this, so only parts will be shown
		t = {}
		t['type'] = self.type
		t['ServiceName'] = self.ServiceName
		t['DomainName'] = self.DomainName
		t['ETargetName'] = self.ETargetName
		t['TargetDomainName'] = self.TargetDomainName
		t['EClientName'] = self.EClientName
		t['AltTargetDomainName'] = self.AltTargetDomainName
		t['StartTime'] = self.StartTime
		t['EndTime'] = self.EndTime
		t['RenewUntil'] = self.RenewUntil
		t['KeyType'] = self.KeyType
		t['Key'] = self.Key
		
		return t
		
	
	def to_asn1(self):
		krbcredinfo = {}
		krbcredinfo['key'] = EncryptionKey({'keytype': self.KeyType, 'keyvalue':self.Key})
		krbcredinfo['prealm'] = self.AltTargetDomainName
		krbcredinfo['pname'] = PrincipalName({'name-type': self.EClientName_type, 'name-string':self.EClientName})
		krbcredinfo['flags'] = core.IntegerBitString(self.TicketFlags).cast(TicketFlags)
		krbcredinfo['starttime'] = self.StartTime
		krbcredinfo['endtime'] = self.EndTime
		krbcredinfo['renew-till'] = self.RenewUntil
		krbcredinfo['srealm'] = self.DomainName
		krbcredinfo['sname'] = PrincipalName({'name-type': self.ServiceName_type, 'name-string':self.ServiceName})
		
		enc_krbcred = {}
		enc_krbcred['ticket-info'] = [KrbCredInfo(krbcredinfo)]
		
		ticket = {}
		ticket['tkt-vno'] = krb5_pvno
		ticket['realm'] = self.DomainName
		ticket['sname'] = PrincipalName({'name-type': NAME_TYPE.SRV_INST.value, 'name-string':self.ServiceName})
		ticket['enc-part'] = EncryptedData({'etype': self.TicketEncType, 'kvno': self.TicketKvno, 'cipher': self.Ticket})
		
		krbcred = {}
		krbcred['pvno'] = krb5_pvno
		krbcred['msg-type'] = MESSAGE_TYPE.KRB_CRED.value
		krbcred['tickets'] = [Ticket(ticket)]
		krbcred['enc-part'] = EncryptedData({'etype': EncryptionType.NULL.value, 'cipher': EncKrbCredPart(enc_krbcred).dump()})
	
		return KRBCRED(krbcred)
	
	@staticmethod
	def parse(kerberos_ticket, reader, sysinfo, type = None):
		kt = KerberosTicket()
		kt.type = type
		kt.ServiceName_type = kerberos_ticket.ServiceName.read(reader).NameType
		kt.ServiceName = kerberos_ticket.ServiceName.read(reader).read(reader)
		kt.DomainName = kerberos_ticket.DomainName.read_string(reader)
		if kerberos_ticket.TargetName.read(reader):
			kt.ETargetName = kerberos_ticket.TargetName.read(reader).read(reader)
			kt.ETargetName_type = kerberos_ticket.TargetName.read(reader).NameType 
		kt.TargetDomainName = kerberos_ticket.TargetDomainName.read_string(reader) 
		kt.EClientName = kerberos_ticket.ClientName.read(reader).read(reader)
		kt.EClientName_type = kerberos_ticket.ClientName.read(reader).NameType
		kt.AltTargetDomainName = kerberos_ticket.AltTargetDomainName.read_string(reader)
		kt.Description = kerberos_ticket.Description.read_string(reader)
		
		kt.StartTime = filetime_to_dt(kerberos_ticket.StartTime)
		kt.EndTime = filetime_to_dt(kerberos_ticket.EndTime)
		if kerberos_ticket.RenewUntil == 0:
			kt.RenewUntil = datetime.datetime(1970, 1, 1, 0, 0, tzinfo=datetime.timezone.utc)
		else:
			kt.RenewUntil = filetime_to_dt(kerberos_ticket.RenewUntil)
		
		kt.KeyType = kerberos_ticket.KeyType
		kt.Key = kerberos_ticket.Key.read(reader)
		kt.session_key = KerberosSessionKey.parse(kerberos_ticket.Key, sysinfo)
		
		kt.TicketFlags = kerberos_ticket.TicketFlags
		kt.TicketEncType = kerberos_ticket.TicketEncType
		kt.TicketKvno = kerberos_ticket.TicketKvno
		kt.Ticket = kerberos_ticket.Ticket.read(reader)
		
		kirbi = kt.to_asn1()
		kt.kirbi_data[kt.generate_filename()] = kirbi
		
		return kt
		
	def generate_filename(self):
		t = '%s' % ('_'.join([self.type.name, self.DomainName, '_'.join(self.EClientName), '_'.join(self.ServiceName), hashlib.sha1(self.Ticket).hexdigest()[:8]]))
		return '%s.kirbi' % t.replace('..','!')
		
	def to_kirbi(self, dir):
		for filename in self.kirbi_data:
			with open(os.path.join(dir, filename), 'wb') as f:
				f.write(self.kirbi_data[filename].dump())
	
	def __str__(self):
		t =  '== Kerberos Ticket ==\n'
		t += 'Type: %s\n'% self.type
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
		t += 'Key: %s\n'% self.Key.hex()
		t += 'TicketFlags: %s\n'% self.TicketFlags
		t += 'TicketEncType: %s\n'% self.TicketEncType
		t += 'TicketKvno: %s\n'% self.TicketKvno
		t += 'Ticket: %s\n'% self.Ticket.hex()	
		t += 'SessionKey: %s\n'% self.session_key.sessionkey.hex()	
	
		return t
		
