from asn1crypto import core
from pypykatz.commons.filetime import *
from pypykatz.commons.common import *
from minikerberos.asn1_structs import *
from minikerberos.ccache import CCACHE
import enum
import os
	
	
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
		
		self.kirbi_data = None
		self.ccache_data = None
		
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
		#input('tb %x' % self.TicketFlags)
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
		
		encpart = {}
		encpart['etype']  = KerberosEncryptonType.NULL.value
		encpart['cipher'] = EncKrbCredPart(enckrbcredpart).dump()
		
		
		encpart = EncryptedData(encpart)
		
		with open('new2.asn1','wb') as f:
			f.write(EncKrbCredPart(enckrbcredpart).dump())
		
		
		krbcred['enc-part'] = encpart
		
		#input('ENCPART: \n%s' % hexdump(encpart.dump()))
		
		return KRBCRED(krbcred)		
		
	def parse(kerberos_ticket, reader):
		kt = KerberosTicket()
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
		kt.EndTime = filetime_to_dt(kerberos_ticket.StartTime)
		kt.RenewUntil = filetime_to_dt(kerberos_ticket.StartTime)
		
		kt.KeyType = kerberos_ticket.KeyType
		kt.Key = kerberos_ticket.Key.read(reader)
		
		kt.TicketFlags = KerberosTicketFlags(kerberos_ticket.TicketFlags)
		kt.TicketEncType = kerberos_ticket.TicketEncType
		kt.TicketKvno = kerberos_ticket.TicketKvno
		kt.Ticket = kerberos_ticket.Ticket.read(reader)
		
		kt.kirbi_data = kt.to_asn1().dump()
		kt.ccache_data = CCACHE.from_kirbi(kt.kirbi_data).to_bytes()
		
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
		