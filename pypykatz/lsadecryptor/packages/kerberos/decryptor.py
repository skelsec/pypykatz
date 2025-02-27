#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
from typing import List
from pypykatz.commons.kerberosticket import KerberosTicket, KerberosTicketType
from pypykatz.lsadecryptor.package_commons import PackageDecryptor
from pypykatz.commons.win_datatypes import PLIST_ENTRY, PRTL_AVL_TABLE
from pypykatz.commons.common import WindowsMinBuild

class KerberosCredential:
	def __init__(self):
		self.credtype:str = 'kerberos'
		self.username:str = None
		self.password:str = None
		self.password_raw:bytes = b''
		self.domainname:str = None
		self.luid:int = None
		self.tickets:List[KerberosTicket] = []
		self.pin:str = None
		self.pin_raw:bytes = None
		self.cardinfo = None
		self.aes_key128 = None
		self.aes_key256 = None
		
	def __str__(self):
		t = '\t== Kerberos ==\n'
		t += '\t\tUsername: %s\n' % self.username
		t += '\t\tDomain: %s\n' % self.domainname
		if self.password is not None:
			t += '\t\tPassword: %s\n' % self.password
			t += '\t\tpassword (hex)%s\n' % self.password_raw.hex()
		if self.pin is not None:
			t += '\t\tPIN: %s\n' % self.pin
			t += '\t\tPIN (hex): %s\n' % self.pin_raw.hex()
		if self.cardinfo is not None:
			t += '\t\tCARDINFO: \n'
			t += '\t\t\tCardName: %s\n' % self.cardinfo['CardName']
			t += '\t\t\tReaderName: %s\n' % self.cardinfo['ReaderName']
			t += '\t\t\tContainerName: %s\n' % self.cardinfo['ContainerName']
			t += '\t\t\tCSPName: %s\n' % self.cardinfo['CSPName']
		if self.aes_key128:
			t += '\t\tAES128 Key: %s\n' % self.aes_key128.hex()
		if self.aes_key256:
			t += '\t\tAES256 Key: %s\n' % self.aes_key256.hex()

		# TODO: check if users actually need this.
		# I think it's not useful to print out the kerberos ticket data as string, as noone uses it directly.
		# It is better to use the -k flag an export the tickets
		#for ticket in self.tickets:
		#	t += '\t\t%s' % str(ticket).replace('\n','\n\t\t\t')[:-3]
		
		return t
		
	def to_dict(self):
		t = {}
		t['credtype'] = self.credtype
		t['username'] = self.username
		t['password'] = self.password
		t['password_raw'] = self.password_raw
		t['domainname'] = self.domainname
		t['luid'] = self.luid
		t['pin'] = self.pin
		t['pin_raw'] = self.pin_raw
		t['cardinfo'] = self.cardinfo
		t['tickets'] = []
		for ticket in self.tickets:
			t['tickets'] = ticket.to_dict()
		if self.aes_key128:
			t['aes128'] = self.aes_key128.hex()
		if self.aes_key256:
			t['aes256'] = self.aes_key256.hex()
		return t
		

class KerberosDecryptor(PackageDecryptor):
	def __init__(self, reader, decryptor_template, lsa_decryptor, sysinfo, with_tickets = True):
		super().__init__('Kerberos', lsa_decryptor, sysinfo, reader)
		self.decryptor_template = decryptor_template
		self.with_tickets = with_tickets
		self.credentials = []
		
		self.current_ticket_type = None
		self.current_cred = None

	def find_first_entry(self):
		self.log('Scanning for Kerberos signature! %s' % self.decryptor_template.signature.hex())
		position = self.find_signature('kerberos.dll',self.decryptor_template.signature)
		self.log('Signature @ %s' % hex(position))
		self.log('Signature (corrected) @ %s' % hex(position + self.decryptor_template.first_entry_offset))
		ptr_entry_loc = self.reader.get_ptr_with_offset(position + self.decryptor_template.first_entry_offset)
		self.log('First entry ptr @ %s' % hex(ptr_entry_loc))
		ptr_entry = self.reader.get_ptr(ptr_entry_loc)
		self.log('First entry -> %s' % hex(ptr_entry))
		return ptr_entry, ptr_entry_loc
	
	def handle_ticket(self, kerberos_ticket):
		try:
			kt = KerberosTicket.parse(kerberos_ticket, self.reader, self.decryptor_template.sysinfo, self.current_ticket_type)
			self.current_cred.tickets.append(kt)
		except Exception as e:
			raise e
	
	def start(self):
		try:
			entry_ptr_value, entry_ptr_loc = self.find_first_entry()
		except Exception as e:
			self.log('Failed to find structs! Reason: %s' % e)
			return
		
		if self.sysinfo.buildnumber < WindowsMinBuild.WIN_VISTA.value:
			self.reader.move(entry_ptr_loc)
			entry_ptr = PLIST_ENTRY(self.reader)
			self.walk_list(entry_ptr, self.process_session_elist)
		else:
			result_ptr_list = []
			self.reader.move(entry_ptr_value)
			start_node = PRTL_AVL_TABLE(self.reader).read(self.reader)
			self.walk_avl(start_node.BalancedRoot.RightChild, result_ptr_list)
			
			for ptr in result_ptr_list:
				self.log_ptr(ptr, self.decryptor_template.kerberos_session_struct.__name__)
				self.reader.move(ptr)
				kerberos_logon_session = self.decryptor_template.kerberos_session_struct(self.reader)
				self.process_session(kerberos_logon_session)

	def process_session_elist(self, elist):
		self.reader.move(elist.location)
		self.reader.read_uint() #Flink do not remove this line!
		self.reader.read_uint() #Blink do not remove this line!
		kerberos_logon_session = self.decryptor_template.kerberos_session_struct(self.reader)
		self.process_session(kerberos_logon_session)

	def process_session(self, kerberos_logon_session):
		self.current_cred = KerberosCredential()
		self.current_cred.luid = kerberos_logon_session.LocallyUniqueIdentifier
		
		self.current_cred.username = kerberos_logon_session.credentials.UserName.read_string(self.reader)
		self.current_cred.domainname = kerberos_logon_session.credentials.Domaine.read_string(self.reader)
		
		# Extract keys from pKeyList
		if kerberos_logon_session.pKeyList.value != 0:
			key_list = kerberos_logon_session.pKeyList.read(self.reader, override_finaltype = self.decryptor_template.keys_list_struct)
			key_list.read(self.reader, self.decryptor_template.hash_password_struct)
			
			for key in key_list.KeyEntries:
				if key.generic.Size > 0:
					if key.generic.Size <= 24: # AES128
						keydata = key.generic.Checksump.read_raw(self.reader, key.generic.Size)
						if keydata:
							dec_key, _ = self.decrypt_password(keydata, bytes_expected=True)
							if dec_key:
								self.current_cred.aes_key128 = dec_key
					elif key.generic.Size <= 32: # AES256
						keydata = key.generic.Checksump.read_raw(self.reader, key.generic.Size)
						if keydata:
							dec_key, _ = self.decrypt_password(keydata, bytes_expected=True)
							if dec_key:
								self.current_cred.aes_key256 = dec_key
		
		# Process normal password if present
		if kerberos_logon_session.credentials.Password.Length != 0:
			if self.current_cred.username.endswith('$') is True:
				self.current_cred.password, self.current_cred.password_raw = self.decrypt_password(
					kerberos_logon_session.credentials.Password.read_maxdata(self.reader), 
					bytes_expected=True
				)
				if self.current_cred.password is not None:
					self.current_cred.password = self.current_cred.password.hex()
			else:
				self.current_cred.password, self.current_cred.password_raw = self.decrypt_password(
					kerberos_logon_session.credentials.Password.read_maxdata(self.reader)
				)
		
		if kerberos_logon_session.SmartcardInfos.value != 0:
			csp_info = kerberos_logon_session.SmartcardInfos.read(self.reader, override_finaltype = self.decryptor_template.csp_info_struct)
			pin_enc = csp_info.PinCode.read_maxdata(self.reader)
			self.current_cred.pin, self.current_cred.pin_raw = self.decrypt_password(pin_enc)
			if csp_info.CspDataLength != 0:
				self.current_cred.cardinfo = csp_info.CspData.get_infos()

		if self.with_tickets is True:
			if kerberos_logon_session.Tickets_1.Flink.value != 0 and \
					kerberos_logon_session.Tickets_1.Flink.value != kerberos_logon_session.Tickets_1.Flink.location and \
						kerberos_logon_session.Tickets_1.Flink.value != kerberos_logon_session.Tickets_1.Flink.location - 4 :
				self.current_ticket_type = KerberosTicketType.TGS
				self.walk_list(kerberos_logon_session.Tickets_1.Flink, self.handle_ticket , override_ptr = self.decryptor_template.kerberos_ticket_struct)
			
			if kerberos_logon_session.Tickets_2.Flink.value != 0 and \
					kerberos_logon_session.Tickets_2.Flink.value != kerberos_logon_session.Tickets_2.Flink.location and \
						kerberos_logon_session.Tickets_2.Flink.value != kerberos_logon_session.Tickets_2.Flink.location - 4 :
				self.current_ticket_type = KerberosTicketType.CLIENT
				self.walk_list(kerberos_logon_session.Tickets_2.Flink,self.handle_ticket , override_ptr = self.decryptor_template.kerberos_ticket_struct)
			
			if kerberos_logon_session.Tickets_3.Flink.value != 0 and \
					kerberos_logon_session.Tickets_3.Flink.value != kerberos_logon_session.Tickets_3.Flink.location and \
						kerberos_logon_session.Tickets_3.Flink.value != kerberos_logon_session.Tickets_3.Flink.location - 4 :
				self.current_ticket_type = KerberosTicketType.TGT
				self.walk_list(kerberos_logon_session.Tickets_3.Flink,self.handle_ticket , override_ptr = self.decryptor_template.kerberos_ticket_struct)
			self.current_ticket_type = None
		self.credentials.append(self.current_cred)
	
	