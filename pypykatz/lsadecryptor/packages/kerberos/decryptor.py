#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import io

#from pypykatz.commons.common import *
#from pypykatz.commons.filetime import *
#from .templates import *
from pypykatz.commons.kerberosticket import KerberosTicket, KerberosTicketType
from pypykatz.lsadecryptor.package_commons import PackageDecryptor
from pypykatz.commons.win_datatypes import PLIST_ENTRY, PRTL_AVL_TABLE
from pypykatz.commons.common import WindowsMinBuild

class KerberosCredential:
	def __init__(self):
		self.credtype = 'kerberos'
		self.username = None
		self.password = None
		self.password_raw = None
		self.domainname = None
		self.luid = None
		self.tickets = []
		self.pin = None
		self.pin_raw = None
		self.cardinfo = None
		
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
		position = self.find_signature('kerberos.dll',self.decryptor_template.signature)
		ptr_entry_loc = self.reader.get_ptr_with_offset(position + self.decryptor_template.first_entry_offset)
		ptr_entry = self.reader.get_ptr(ptr_entry_loc)
		return ptr_entry, ptr_entry_loc
	
	def handle_ticket(self, kerberos_ticket):
		try:
			kt = KerberosTicket.parse(kerberos_ticket, self.reader, self.decryptor_template.sysinfo, self.current_ticket_type)
			self.current_cred.tickets.append(kt)
			#print(str(kt))
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
		if self.current_cred.username.endswith('$') is True:
			self.current_cred.password, self.current_cred.password_raw = self.decrypt_password(kerberos_logon_session.credentials.Password.read_maxdata(self.reader), bytes_expected=True)
			if self.current_cred.password is not None:
				self.current_cred.password = self.current_cred.password.hex()
		else:
			self.current_cred.password, self.current_cred.password_raw = self.decrypt_password(kerberos_logon_session.credentials.Password.read_maxdata(self.reader))
		
		if kerberos_logon_session.SmartcardInfos.value != 0:
			csp_info = kerberos_logon_session.SmartcardInfos.read(self.reader, override_finaltype = self.decryptor_template.csp_info_struct)
			pin_enc = csp_info.PinCode.read_maxdata(self.reader)
			self.current_cred.pin, self.current_cred.pin_raw = self.decrypt_password(pin_enc)
			if csp_info.CspDataLength != 0:
				self.current_cred.cardinfo = csp_info.CspData.get_infos()

		#### key list (still in session) this is not a linked list (thank god!)
		if kerberos_logon_session.pKeyList.value != 0:
			key_list = kerberos_logon_session.pKeyList.read(self.reader, override_finaltype = self.decryptor_template.keys_list_struct)
			#print(key_list.cbItem)
			key_list.read(self.reader, self.decryptor_template.hash_password_struct)
			for key in key_list.KeyEntries:
				pass
				### GOOD
				#keydata_enc = key.generic.Checksump.read_raw(self.reader, key.generic.Size)
				#print(keydata_enc)
				#keydata, raw_dec = self.decrypt_password(keydata_enc, bytes_expected=True)
				#print(keydata_enc.hex())
				#input('KEY?')


				#print(key.generic.Checksump.value)
				
				#self.log_ptr(key.generic.Checksump.value, 'Checksump', datasize = key.generic.Size)
				#if self.reader.reader.sysinfo.BuildNumber < WindowsBuild.WIN_10_1507.value and key.generic.Size > LSAISO_DATA_BLOB.size:
				#	if key.generic.Size <= LSAISO_DATA_BLOB.size + (len("KerberosKey") - 1) + 32: #AES_256_KEY_LENGTH
				#		input('1')
				#		data_blob = key.generic.Checksump.read(self.reader, override_finaltype = LSAISO_DATA_BLOB)
				#		data_blob.read(self.reader, key.generic.Size - LSAISO_DATA_BLOB.size)
				#		
				#		input('data blob end')
				#		"""
				#		kprintf(L"\n\t   * LSA Isolated Data: %.*S", blob->typeSize, blob->data);
				#		kprintf(L"\n\t     Unk-Key  : "); kull_m_string_wprintf_hex(blob->unkKeyData, sizeof(blob->unkKeyData), 0);
				#		kprintf(L"\n\t     Encrypted: "); kull_m_string_wprintf_hex(blob->data + blob->typeSize, blob->origSize, 0);
				#		kprintf(L"\n\t\t   SS:%u, TS:%u, DS:%u", blob->structSize, blob->typeSize, blob->origSize);
				#		kprintf(L"\n\t\t   0:0x%x, 1:0x%x, 2:0x%x, 3:0x%x, 4:0x%x, E:", blob->unk0, blob->unk1, blob->unk2, blob->unk3, blob->unk4);
				#		kull_m_string_wprintf_hex(blob->unkData2, sizeof(blob->unkData2), 0); kprintf(L", 5:0x%x", blob->unk5);
				#		"""
				#	else:
				#		input('2')
				#		key.generic.Checksump.read(self.reader, override_finaltype = LSAISO_DATA_BLOB)
				#		print('unkData1 : %s' % data_struct.unkData1.hex())
				#		print('unkData2 : %s' % data_struct.unkData2.hex())
				#		print('Encrypted : %s' % data_struct.data.hex()) #another extra struct should wrap this data! ENC_LSAISO_DATA_BLOB
				#		
				#else:
				#	
				#	if self.reader.reader.sysinfo.BuildNumber < WindowsBuild.WIN_VISTA.value:
				#		input('3')
				#		key.generic.Checksump.read(self.reader, override_finaltype = LSAISO_DATA_BLOB)
				#		print('unkData1 : %s' % data_struct.unkData1.hex())
				#		print('unkData2 : %s' % data_struct.unkData2.hex())
				#		print('Encrypted : %s' % data_struct.data.hex()) #another extra struct should wrap this data! ENC_LSAISO_DATA_BLOB
				#		
				#	else:
				#		input('4')
				#		#we need to decrypt as well!
				#		self.reader.move(key.generic.Checksump.value)
				#		enc_data = self.reader.read(key.generic.Size)
				#		print(hexdump(enc_data))
				#		dec_data = self.lsa_decryptor.decrypt(enc_data)
				#		print(hexdump(dec_data))
				#		t_reader = GenericReader(dec_data)
				#		data_struct = LSAISO_DATA_BLOB(t_reader)
				#		print('unkData1 : %s' % data_struct.unkData1.hex())
				#		print('unkData2 : %s' % data_struct.unkData2.hex())
				#		print('Encrypted : %s' % data_struct.data.hex()) #another extra struct should wrap this data! ENC_LSAISO_DATA_BLOB
				#
				#input()
		
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
	
	