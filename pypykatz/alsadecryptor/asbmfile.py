
import math

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
		self.cache = []
		self.curpos = 0

	async def open(self, connection, mode = 'r'):
		return await self.smbfile.open(connection, mode=mode)
		 

	async def read(self, n = -1):
		#print('read %s' % n)
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
		# requested data not found in cache, this case we will read a larger chunk than requested and store it in memory
		# since reading more data skews the current position we will need to reset the position by calling seek with the correct pos

		readsize = min(self.smbfile.maxreadsize, self.smbfile.size)
		buffer = b''

		# this is needed bc sometimes the readsize is smaller than the requested amount
		for _ in range(int(math.ceil(n/readsize))):
			data, err = await self.smbfile.read(readsize)
			if err is not None:
				raise err
			buffer += data
		
		section = FileSection(self.curpos, buffer)
		self.cache.append(section)
		
		data = section.read(self.curpos, n)
		await self.seek(self.curpos + n, 0)
		return data
	
	async def close(self):
		return await self.smbfile.close()
	
	async def delete(self):
		return await self.smbfile.delete()
	
	def tell(self):
		return self.curpos
	
	async def seek(self, n, whence = 0):
		#print('seek %s %s' % (whence, n))
		_, err = await self.smbfile.seek(n, whence)
		if err is not None:
			raise err
		self.curpos = self.smbfile.tell()