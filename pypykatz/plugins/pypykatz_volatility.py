# https://github.com/volatilityfoundation/community/blob/master/FrancescoPicasso/mimikatz.py
# https://github.com/TazWake/volatility-plugins/blob/master/ramscan/ramscan.py
import volatility.plugins.common as common
import volatility.utils as utils
import volatility.win32 as win32

class VolatilityVadSegment:
	def __init__(self):
		self.vad = vad
		self.start_address = vad.Start
		self.end_address = vad.End
		self.size = start_address - end_address
		
class VolatilityModule:
	def __init__(self):
		self.name = None
		self.baseaddress = None
		self.size = None
		self.endaddress = None
		
		self.versioninfo = None
		self.checksum = None
		self.timestamp = None
		
		
	def parse(mod):
		"""
		mod: volatility module obje
		buff: file handle
		"""
		mm = VolatilityModule()
		mm.name = mod.FullDllName
		
		mm.baseaddress = mod.DllBase
		mm.size = mod.SizeOfImage
		mm.endaddress = mm.baseaddress + mm.size
		
		mm.checksum = mod.CheckSum
		mm.timestamp = mod.TimeDateStamp
		mm.versioninfo = mod.VersionInfo
		
		return mm
		
	def __str__(self):
		return 'Module name: %s BaseAddress: 0x%08x Size: 0x%x Endaddress: 0x%08x' % (self.name, self.baseaddress, self.size, self.endaddress)

class VolatilityReader:
	def __init__(self):
		self.vads = []
		self.modules = []
		
		
		
	def start(self):
		self.lsass_task = self.find_lsass()
		if not lsass_task:
			debug.error('lsass_task process not found!!')
			return
		
	
	def find_lsass(self):
		addr_space = utils.load_as(self._config)
		for task in tasks.pslist(addr_space):
			if str(task.ImageFileName) == 'lsass.exe':
				return task
		
	def get_vads(self):
		process_space = self.lsass_task.get_process_address_space()
		for vad in task.VadRoot.traverse():
			if vad != None: 
				v = VadSegment(vad)
				self.vads.append(v)
				
				
                data = process_space.read(vad.Start, 1024)
                if vad.u.VadFlags.CommitCharge.v() > 30:
				
	def get_modules(self):
		for mod in self.lsass_task.get_load_modules():
			
		
		
	
