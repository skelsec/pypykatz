
async def dcsync(url, username = None):
	from aiosmb.commons.connection.url import SMBConnectionURL
	from aiosmb.commons.interfaces.machine import SMBMachine

	smburl = SMBConnectionURL(url)
	connection = smburl.get_connection()

	users = []
	if username is not None:
		users.append(username)

	async with connection:
		_, err = await connection.login()
		if err is not None:
			raise err

		async with SMBMachine(connection) as machine:
			async for secret, err in machine.dcsync(target_users=users):
				if err is not None:
					raise err
				yield secret