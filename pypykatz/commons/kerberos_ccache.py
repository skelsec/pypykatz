
# http://repo.or.cz/w/krb5dissect.git/blob_plain/HEAD:/ccache.txt
class Header:
	def __init__(self):
		self.tag = None
		self.taglen = None
		self.tagdata = None
		
	def parse(reader):
		h = Header()
		h.tag = int.from_bytes(reader.read(2), byteorder='big', signed=False)
		h.taglen = int.from_bytes(reader.read(2), byteorder='big', signed=False)
		h.tagdata = reader.read(h.taglen)
		return h
		
	def to_bytes(self):
		t =  self.tag.to_bytes(2, byteorder='big', signed=False)
		t += self.taglen.to_bytes(2, byteorder='big', signed=False)
		t += self.tagdata
		return t

class DateTime:
	def __init__(self):
		self.time_offset = None
		self.usec_offset = None
		
	def parse(reader):
		d = DateTime()
		d.time_offset = int.from_bytes(reader.read(4), byteorder='big', signed=False)
		d.usec_offset = int.from_bytes(reader.read(4), byteorder='big', signed=False)
		return d
		
	def to_bytes(self):
		t =  self.time_offset.to_bytes(4, byteorder='big', signed=False)
		t += self.usec_offset.to_bytes(4, byteorder='big', signed=False)
		return t
		

		
class Credential:
	def __init__(self):
		self.client = none
		self.server = None
		self.key = None
		self.is_skey = None
		self.tktflags = None
		self.num_address = None
		self.addrs = []
		self.num_authdata = None
		self.authdata = []
		self.ticket = None
		self.second_ticket = None
		
	def parse(reader):
		c = Credential()
		c.client = Principal.parse(reader)
		c.server = Principal.parse(reader)
		c.key = Keyblock.parse(reader)
		c.is_skey = int.from_bytes(reader.read(1), byteorder='big', signed=False)
		c.tktflags = int.from_bytes(reader.read(4), byteorder='little', signed=False)
		c.num_address = int.from_bytes(reader.read(4), byteorder='big', signed=False)
		for i in range(c.num_address):
			c.addrs.append(Address.parse(reader))
		c.num_authdata = int.from_bytes(reader.read(4), byteorder='big', signed=False)
		for i in range(c.num_authdata):
			c.authdata.append(Authdata.parse(reader))
		c.ticket = OctetString.parse(reader)
		c.second_ticket = OctetString.parse(reader)
		return h
		
	def to_bytes(self):
		t =  self.client.to_bytes()
		t += self.server.to_bytes()
		t += self.key.to_bytes()
		t += self.is_skey.to_bytes(1, byteorder='big', signed=False)
		t += self.tktflags.to_bytes(4, byteorder='little', signed=False)
		t += self.num_address.to_bytes(4, byteorder='big', signed=False)
		for addr in self.addrs:
			t += addr.to_bytes()
		t += self.num_authdata.to_bytes(4, byteorder='big', signed=False)
		for ad in self.authdata:
			t += ad.to_bytes()
		t += self.ticket.to_bytes()
		t += self.second_ticket.to_bytes()
		return t
		
class Keyblock:
	def __init__(self):
		self.keytype = None
		self.etype = None
		self.keylen = None
		self.keyvalue = None
		
	def parse(reader):
		k = Keyblock()
		k.keytype = int.from_bytes(reader.read(2), byteorder='big', signed=False)
		k.etype = int.from_bytes(reader.read(2), byteorder='big', signed=False)
		k.keylen = int.from_bytes(reader.read(2), byteorder='big', signed=False)
		k.keyvalue = reader.read(k.keylen)
		return k
		
	def to_bytes(self):
		t = self.keytype.to_bytes(2, byteorder='big', signed=False)
		t += self.etype.to_bytes(2, byteorder='big', signed=False)
		t += self.keylen.to_bytes(2, byteorder='big', signed=False)
		t += self.keyvalue
		return t
		
		
class Times:
	def __init__(self):
		self.authtime = None
		self.starttime = None
		self.endtime = None
		self.renew_till = None
		
	def parse(reader):
		t = Times()
		t.authtime = int.from_bytes(reader.read(4), byteorder='big', signed=False)
		t.starttime = int.from_bytes(reader.read(4), byteorder='big', signed=False)
		t.endtime = int.from_bytes(reader.read(4), byteorder='big', signed=False)
		t.renew_till = int.from_bytes(reader.read(4), byteorder='big', signed=False)
		return t
		
	def to_bytes(self):
		t = self.authtime.to_bytes(4, byteorder='big', signed=False)
		t += self.starttime.to_bytes(4, byteorder='big', signed=False)
		t += self.endtime.to_bytes(4, byteorder='big', signed=False)
		t += self.renew_till.to_bytes(4, byteorder='big', signed=False)
		return t
		
class Address:
	def __init__(self):
		self.addrtype = None
		self.addrdata = None
		
	def parse(reader):
		a = Address()
		a.addrtype = int.from_bytes(reader.read(2), byteorder='big', signed=False)
		a.addrdata = OctetString.parse(reader)
		return a
		
	def to_bytes(self):
		t = self.addrtype.to_bytes(2, byteorder='big', signed=False)
		t += self.addrdata.to_bytes()
		return t
		
class Authdata:
	def __init__(self):
		self.authtype = None
		self.authdata = None
	
	def parse(reader):
		a = Authdata()
		a.authtype = int.from_bytes(reader.read(2), byteorder='big', signed=False)
		a.authdata = OctetString.parse(reader)
		return a
		
	def to_bytes(self):
		t = self.authtype.to_bytes(2, byteorder='big', signed=False)
		t += self.authdata.to_bytes()
		return t
		
class Principal:
	def __init__(self):
		self.name_type = none
		self.num_components = None
		self.realm = None
		self.components = []
		
	def parse(reader):
		p = Principal()
		p.name_type = int.from_bytes(reader.read(4), byteorder='big', signed=False)
		p.num_components = int.from_bytes(reader.read(4), byteorder='big', signed=False)
		p.realm = OctetString.parse(reader)
		for i in range(p.num_components):
			p.components.append(OctetString.parse(reader))
		return p
		
	def to_bytes(self):
		t = self.name_type.to_bytes(4, byteorder='big', signed=False)
		t += self.num_components.to_bytes(4, byteorder='big', signed=False)
		t += self.realm.to_bytes()
		for com in self.components:
			t += com.to_bytes()
		return t
		
class OctetString:
	def __init__(self):
		self.length = None
		self.data = None
	
	def parse(reader):
		o = OctetString()
		o.length = int.from_bytes(reader.read(4), byteorder='big', signed=False)
		o.data = reader.read(o.length)
		return o
		
	def to_bytes(self):
		t = self.length.to_bytes(4, byteorder='big', signed=False)
		t += self.data
		return t	
	
		
class CCACHEFile:
	def __init__(self):
		self.file_format_version = None
		self.headerlen = None
		self.headers = []
		self.primary_principal = None
		self.credentials = []
		
	def parse(reader):
		c = CCACHEFile()
		c.file_format_version = int.from_bytes(reader.read(2), byteorder='big', signed=False)
		c.headerlen = int.from_bytes(reader.read(2), byteorder='big', signed=False)
		for i in range(c.headerlen):
			c.headers.append(Header.parse(reader))
		c.primary_principal = Principal.parse(reader)
		pos = reader.tell()
		reader.seek(-1,2)
		eof = reader.tell()
		reader.seek(pos,0)
		while reader.tell() != eof:
			self.credentials.append(Credential.parse(reader))
		
		return c
		
	def to_bytes(self):
		t = self.file_format_version.to_bytes(2, byteorder='big', signed=False)
		t += self.headerlen.to_bytes(2, byteorder='big', signed=False)
		for header in self.headers:
			t += header.to_bytes()
		t += self.primary_principal.to_bytes()
		for cred in self.credentials:
			t += cred.to_bytes()
		return t
		
	def from_file(filename):
		with open(filename, 'rb') as f:
			return CCACHEFile.parse(f)
			
	def to_file(self, filename):
		with open(filename, 'wb') as f:
			f.write(self.to_bytes())
		
