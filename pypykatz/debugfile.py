
import sys
import traceback
import asyncio

from pypykatz.pypykatz import pypykatz
from pypykatz.apypykatz import apypykatz

class DebugFile:
	def __init__(self, filename):
		self.filename = filename
		self.fh = open(self.filename, 'rb')

		self.reads = []
		self.total_read = 0
	
	def read(self, n = -1):
		#print('READ %s' % n)
		self.reads.append((self.fh.tell(), n))
		self.total_read += n
		#if n > 1024*40:
		#	print('READ %s' % n)
		#	traceback.print_stack()
		#	input()
		return self.fh.read(n)
	
	def seek(self, n, whence = 0):
		#print('SEEK %s %s' % (n, whence))
		return self.fh.seek(n, whence)
	
	def tell(self):
		return self.fh.tell()

class ADebugFile:
	def __init__(self, filename):
		self.filename = filename
		self.fh = open(self.filename, 'rb')

		self.reads = []
		self.total_read = 0
	
	async def read(self, n = -1):
		#print('READ %s' % n)
		self.reads.append((self.fh.tell(), n))
		self.total_read += n
		#if n > 1024*40:
		#	print('READ %s' % n)
		#	traceback.print_stack()
		#	input()
		return self.fh.read(n)
	
	async def seek(self, n, whence = 0):
		#print('SEEK %s %s' % (n, whence))
		return self.fh.seek(n, whence)
	
	def tell(self):
		return self.fh.tell()

async def amain():
	for chk in [512,1024,5*1024,10*1024,20*1024,50*1024]:
		f = ADebugFile(sys.argv[1])
		mimi = await apypykatz.parse_minidump_external(f, chunksize=chk, packages=['all'])
		res = sorted(f.reads, key=lambda x: x[0])
		i = 0
		for pos, n in res:
			#print('READ: %s %s' % (pos, n))
			if n < 1024:
				i += 1
		print('chk : %s' % chk)
		print('reads: %s' % len(f.reads))
		print('small reads: %s' % i)
		print('total reads: %s' % (f.total_read))
		print('')
	print('DONE!')


def main():
	for chk in [512,1024,5*1024,10*1024,20*1024,50*1024]:
		f = DebugFile(sys.argv[1])
		mimi = pypykatz.parse_minidump_external(f, chunksize=chk, packages=['all'])
		res = sorted(f.reads, key=lambda x: x[0])
		i = 0
		for pos, n in res:
			#print('READ: %s %s' % (pos, n))
			if n < 1024:
				i += 1
		print('chk : %s' % chk)
		print('reads: %s' % len(f.reads))
		print('small reads: %s' % i)
		print('total reads: %s' % (f.total_read))
		print('')
	print('DONE!')

if __name__ == '__main__':
	#main()
	asyncio.run(amain())