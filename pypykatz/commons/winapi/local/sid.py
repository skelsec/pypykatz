import io
import ctypes

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f992ad60-0fe4-4b87-9fed-beb478836861
class SID:
	def __init__(self):
		self.Revision = None
		self.SubAuthorityCount = None
		self.IdentifierAuthority = None
		self.SubAuthority = []
		
		self.wildcard = None #this is for well-known-sid lookups
	
	@staticmethod	
	def from_string(sid_str, wildcard = False):
		if sid_str[:4] != 'S-1-':
			raise Exception('This is not a SID')
		sid = SID()
		sid.wildcard = wildcard
		sid.Revision = 1
		sid_str = sid_str[4:]
		t = sid_str.split('-')[0]
		if t[:2] == '0x':
			print(t[2:])
			sid.IdentifierAuthority = int(t[2:],16)
		else:
			sid.IdentifierAuthority = int(t)
			
		for p in sid_str.split('-')[1:]:
			try:
				p = int(p)
			except Exception as e:
				if wildcard != True:
					raise e
			sid.SubAuthority.append(p)
		return sid
		
	@staticmethod
	def from_address(addr):
		data = ctypes.string_at(addr, size = 8)
		cnt = data[1] #SubAuthorityCount
		data += ctypes.string_at(addr+8, size = (cnt*4))
		return SID.from_bytes(data)
		
	@staticmethod
	def from_bytes(data):
		return SID.from_buffer(io.BytesIO(data))
		
	@staticmethod
	def from_buffer(buff):
		sid = SID()
		sid.Revision = int.from_bytes(buff.read(1), 'little', signed = False)
		sid.SubAuthorityCount = int.from_bytes(buff.read(1), 'little', signed = False)
		sid.IdentifierAuthority = int.from_bytes(buff.read(6), 'big', signed = False)
		for i in range(sid.SubAuthorityCount):
			sid.SubAuthority.append(int.from_bytes(buff.read(4), 'little', signed = False))
		return sid
		
	def to_bytes(self):
		t = self.Revision.to_bytes(1, 'little')
		t += len(self.SubAuthority).to_bytes(1, 'little')
		t += self.IdentifierAuthority.to_bytes(6, 'big')
		for i in self.SubAuthority:
			t += i.to_bytes((i.bit_length() + 7) // 8, 'little')
		return t
		
	def __str__(self):
		t = 'S-1-'
		if self.IdentifierAuthority < 2**32:
			t += str(self.IdentifierAuthority)
		else:
			t += '0x' + self.IdentifierAuthority.to_bytes(6, 'big').hex().upper().rjust(12, '0')
		for i in self.SubAuthority:
			t += '-' + str(i)
		return t

well_known_sids = {
	'NULL' : SID.from_string('S-1-0-0', True),
	'EVERYONE' : SID.from_string('S-1-1-0', True),
	'LOCAL' : SID.from_string('S-1-2-0', True),
	'CONSOLE_LOGON' : SID.from_string('S-1-2-1', True),
	'CREATOR_OWNER' : SID.from_string('S-1-3-0', True),
	'CREATOR_GROUP' : SID.from_string('S-1-3-1', True),
	'OWNER_SERVER' : SID.from_string('S-1-3-2', True),
	'GROUP_SERVER' : SID.from_string('S-1-3-3', True),
	'OWNER_RIGHTS' : SID.from_string('S-1-3-4', True),
	'NT_AUTHORITY' : SID.from_string('S-1-5', True),
	'DIALUP' : SID.from_string('S-1-5-1', True),
	'NETWORK' : SID.from_string('S-1-5-2', True),
	'BATCH' : SID.from_string('S-1-5-3', True),
	'INTERACTIVE' : SID.from_string('S-1-5-4', True),
	'LOGON_ID' : SID.from_string('S-1-5-5-x-y', True),
	'SERVICE' : SID.from_string('S-1-5-6', True),
	'ANONYMOUS' : SID.from_string('S-1-5-7', True),
	'PROXY' : SID.from_string('S-1-5-8', True),
	'ENTERPRISE_DOMAIN_CONTROLLERS' : SID.from_string('S-1-5-9', True),
	'PRINCIPAL_SELF' : SID.from_string('S-1-5-10', True),
	'AUTHENTICATED_USERS' : SID.from_string('S-1-5-11', True),
	'RESTRICTED_CODE' : SID.from_string('S-1-5-12', True),
	'TERMINAL_SERVER_USER' : SID.from_string('S-1-5-13', True),
	'REMOTE_INTERACTIVE_LOGON' : SID.from_string('S-1-5-14', True),
	'THIS_ORGANIZATION' : SID.from_string('S-1-5-15', True),
	'IUSR' : SID.from_string('S-1-5-17', True),
	'LOCAL_SYSTEM' : SID.from_string('S-1-5-18', True),
	'LOCAL_SERVICE' : SID.from_string('S-1-5-19', True),
	'NETWORK_SERVICE' : SID.from_string('S-1-5-20', True),
	'ENTERPRISE_READONLY_DOMAIN_CONTROLLERS' : SID.from_string('S-1-5-21-<root domain>-498', True),
	'COMPOUNDED_AUTHENTICATION' : SID.from_string('S-1-5-21-0-0-0-496', True),
	'CLAIMS_VALID' : SID.from_string('S-1-5-21-0-0-0-497', True),
	'ADMINISTRATOR' : SID.from_string('S-1-5-21-<machine>-500', True),
	'GUEST' : SID.from_string('S-1-5-21-<machine>-501', True),
	'KRBTG' : SID.from_string('S-1-5-21-<domain>-502', True),
	'DOMAIN_ADMINS' : SID.from_string('S-1-5-21-<domain>-512', True),
	'DOMAIN_USERS' : SID.from_string('S-1-5-21-<domain>-513', True),
	'DOMAIN_GUESTS' : SID.from_string('S-1-5-21-<domain>-514', True),
	'DOMAIN_COMPUTERS' : SID.from_string('S-1-5-21-<domain>-515', True),
	'DOMAIN_DOMAIN_CONTROLLERS' : SID.from_string('S-1-5-21-<domain>-516', True),
	'CERT_PUBLISHERS' : SID.from_string('S-1-5-21-<domain>-517', True),
	'SCHEMA_ADMINISTRATORS' : SID.from_string('S-1-5-21-<root-domain>-518', True),
	'ENTERPRISE_ADMINS' : SID.from_string('S-1-5-21-<root-domain>-519', True),
	'GROUP_POLICY_CREATOR_OWNERS' : SID.from_string('S-1-5-21-<domain>-520', True),
	'READONLY_DOMAIN_CONTROLLERS' : SID.from_string('S-1-5-21-<domain>-521', True),
	'CLONEABLE_CONTROLLERS' : SID.from_string('S-1-5-21-<domain>-522', True),
	'PROTECTED_USERS' : SID.from_string('S-1-5-21-<domain>-525', True),
	'KEY_ADMINS' : SID.from_string('S-1-5-21-<domain>-526', True),
	'ENTERPRISE_KEY_ADMINS' : SID.from_string('S-1-5-21-<domain>-527', True),
	'RAS_SERVERS' : SID.from_string('S-1-5-21-<domain>-553', True),
	'ALLOWED_RODC_PASSWORD_REPLICATION_GROUP' : SID.from_string('S-1-5-21-<domain>-571', True),
	'DENIED_RODC_PASSWORD_REPLICATION_GROUP' : SID.from_string('S-1-5-21-<domain>-572', True),
	'BUILTIN_ADMINISTRATORS' : SID.from_string('S-1-5-32-544', True),
	'BUILTIN_USERS' : SID.from_string('S-1-5-32-545', True),
	'BUILTIN_GUESTS' : SID.from_string('S-1-5-32-546', True),
	'POWER_USERS' : SID.from_string('S-1-5-32-547', True),
	'ACCOUNT_OPERATORS' : SID.from_string('S-1-5-32-548', True),
	'SERVER_OPERATORS' : SID.from_string('S-1-5-32-549', True),
	'PRINTER_OPERATORS' : SID.from_string('S-1-5-32-550', True),
	'BACKUP_OPERATORS' : SID.from_string('S-1-5-32-551', True),
	'REPLICATOR' : SID.from_string('S-1-5-32-552', True),
	'ALIAS_PREW2KCOMPACC' : SID.from_string('S-1-5-32-554', True),
	'REMOTE_DESKTOP' : SID.from_string('S-1-5-32-555', True),
	'NETWORK_CONFIGURATION_OPS' : SID.from_string('S-1-5-32-556', True),
	'INCOMING_FOREST_TRUST_BUILDERS' : SID.from_string('S-1-5-32-557', True),
	'PERFMON_USERS' : SID.from_string('S-1-5-32-558', True),
	'PERFLOG_USERS' : SID.from_string('S-1-5-32-559', True),
	'WINDOWS_AUTHORIZATION_ACCESS_GROUP' : SID.from_string('S-1-5-32-560', True),
	'TERMINAL_SERVER_LICENSE_SERVERS' : SID.from_string('S-1-5-32-561', True),
	'DISTRIBUTED_COM_USERS' : SID.from_string('S-1-5-32-562', True),
	'IIS_IUSRS' : SID.from_string('S-1-5-32-568', True),
	'CRYPTOGRAPHIC_OPERATORS' : SID.from_string('S-1-5-32-569', True),
	'EVENT_LOG_READERS' : SID.from_string('S-1-5-32-573', True),
	'CERTIFICATE_SERVICE_DCOM_ACCESS' : SID.from_string('S-1-5-32-574', True),
	'RDS_REMOTE_ACCESS_SERVERS' : SID.from_string('S-1-5-32-575', True),
	'RDS_ENDPOINT_SERVERS' : SID.from_string('S-1-5-32-576', True),
	'RDS_MANAGEMENT_SERVERS' : SID.from_string('S-1-5-32-577', True),
	'HYPER_V_ADMINS' : SID.from_string('S-1-5-32-578', True),
	'ACCESS_CONTROL_ASSISTANCE_OPS' : SID.from_string('S-1-5-32-579', True),
	'REMOTE_MANAGEMENT_USERS' : SID.from_string('S-1-5-32-580', True),
	'WRITE_RESTRICTED_CODE' : SID.from_string('S-1-5-33', True),
	'NTLM_AUTHENTICATION' : SID.from_string('S-1-5-64-10', True),
	'SCHANNEL_AUTHENTICATION' : SID.from_string('S-1-5-64-14', True),
	'DIGEST_AUTHENTICATION' : SID.from_string('S-1-5-64-21', True),
	'THIS_ORGANIZATION_CERTIFICATE' : SID.from_string('S-1-5-65-1', True),
	'NT_SERVICE' : SID.from_string('S-1-5-80', True),
	'USER_MODE_DRIVERS' : SID.from_string('S-1-5-84-0-0-0-0-0', True),
	'LOCAL_ACCOUNT' : SID.from_string('S-1-5-113', True),
	'LOCAL_ACCOUNT_AND_MEMBER_OF_ADMINISTRATORS_GROUP' : SID.from_string('S-1-5-114', True),
	'OTHER_ORGANIZATION' : SID.from_string('S-1-5-1000', True),
	'ALL_APP_PACKAGES' : SID.from_string('S-1-15-2-1', True),
	'ML_UNTRUSTED' : SID.from_string('S-1-16-0', True),
	'ML_LOW' : SID.from_string('S-1-16-4096', True),
	'ML_MEDIUM' : SID.from_string('S-1-16-8192', True),
	'ML_MEDIUM_PLUS' : SID.from_string('S-1-16-8448', True),
	'ML_HIGH' : SID.from_string('S-1-16-12288', True),
	'ML_SYSTEM' : SID.from_string('S-1-16-16384', True),
	'ML_PROTECTED_PROCESS' : SID.from_string('S-1-16-20480', True),
	'ML_SECURE_PROCESS' : SID.from_string('S-1-16-28672', True),
	'AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY' : SID.from_string('S-1-18-1', True),
	'SERVICE_ASSERTED_IDENTITY' : SID.from_string('S-1-18-2', True),
	'FRESH_PUBLIC_KEY_IDENTITY' : SID.from_string('S-1-18-3', True),
	'KEY_TRUST_IDENTITY' : SID.from_string('S-1-18-4', True),
	'KEY_PROPERTY_MFA' : SID.from_string('S-1-18-5', True),
	'KEY_PROPERTY_ATTESTATION' : SID.from_string('S-1-18-6', True),
}
