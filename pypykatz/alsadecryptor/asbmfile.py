

class FileSection:
	def __init__(self, startpos, data):
		self.startpos = startpos
		self.endpos = startpos + len(data)
		self.data = data

	def inrange(self, start, size):
		if start >= self.startpos and (start+size) <= self.endpos:
			return True
		return False
	
	def read(self, start, size):
		return self.data[ start - self.startpos : (start - self.startpos) + size]

class SMBFileReader:
	def __init__(self, smbfile):
		self.smbfile = smbfile
		self.maxreadsize = smbfile.maxreadsize
		self.cache = []
		self.curpos = 0

	async def read(self, n = -1):
		if n == 0:
			return b''

		if n != -1:
			for section in self.cache:
				if section.inrange(self.curpos, n) is True:
					#print(n)
					data = section.read(self.curpos, n)					
					#print(data)
					await self.seek(n, 1)
					return data

		#print('CACHE MISS!')

		data, err = await self.smbfile.read(self.maxreadsize)
		if err is not None:
			raise err
		
		section = FileSection(self.curpos, data)
		self.cache.append(section)
		
		data = section.read(self.curpos, n)
		#print(n)
		#print(data)
		await self.seek(n, 1)
		return data
	
	async def close(self):
		await self.smbfile.close()
	
	def tell(self):
		return self.curpos
	
	async def seek(self, n, whence = 0):
		_, err = await self.smbfile.seek(n, whence)
		if err is not None:
			raise err
		self.curpos = self.smbfile.tell()