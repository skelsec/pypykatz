
from threading import Thread
from multiprocessing import Process, Queue
from pypykatz import logger

from pypykatz.commons.winapi.local.function_defs.netapi32 import NetShareEnum
from pypykatz.remote.live.common.common import is_port_up


class ShareEnumThread(Thread):
	def __init__(self, inQ, outQ, timeout = 1, pre_check = True):
		Thread.__init__(self)
		self.inQ = inQ
		self.outQ = outQ
		self.timeout = timeout
		self.pre_check = pre_check
		
	def run(self):
		while True:
			target = self.inQ.get()
			if not target:
				break
			if self.pre_check is True:
				if is_port_up(target, 445, timeout = self.timeout) is False:
					continue
			
			try:
				for share in NetShareEnum(target, level=1):
					self.outQ.put((target, share))
			except Exception as e:
				logger.debug('ShareEnumerator error: %s' % str(e))
				continue
		
class ShareEnumProc(Process):
	def __init__(self, inQ, outQ, threadcnt, timeout = 1, pre_check = True):
		Process.__init__(self)
		self.inQ = inQ
		self.outQ = outQ
		self.threadcnt = threadcnt
		self.threads = []
		self.timeout = timeout
		self.pre_check = pre_check
		
	def run(self):
		for i in range(self.threadcnt):
			t = ShareEnumThread(self.inQ, self.outQ, timeout = self.timeout, pre_check = self.pre_check)
			t.daemon = True
			t.start()
			self.threads.append(t)			
		for t in self.threads:
			t.join()
		
class SMResProc(Process):
	def __init__(self, outQ):
		Process.__init__(self)
		self.outQ = outQ
		
	def setup(self):
		return
	
	def run(self):
		self.setup()
		while True:
			result = self.outQ.get()
			if not result:
				break
			
			target, share = result
			
			result = '%s %s %s %s %s' % (target, share.netname, share.type, share.remark, share.passwd)
			
			print(result)
			

class ShareEnumerator:
	def __init__(self):
		self.hosts = []
		self.inQ = Queue()
		self.outQ = Queue()
		self.agents = []
		self.result_process = None
		
		self.agent_proccnt = 4
		self.agent_threadcnt = 4
		
		self.timeout = 1
		self.pre_check = True
		
		
	def load_targets_ldap(self, ldap):
		ldap_filter = r'(&(sAMAccountType=805306369))'

		attributes = ['sAMAccountName']
		for entry in ldap.pagedsearch(ldap_filter, attributes):
			self.hosts.append(entry['attributes']['sAMAccountName'][:-1])
			
	def load_targets_file(self, filename):
		with open(filename,'r') as f:
			for line in f:
				line=line.strip()
				if line == '':
					continue
				self.hosts.append(line)
				
	def load_tagets(self, targets):
		self.hosts += targets
		
	def run(self):
		self.result_process = SMResProc(self.outQ)
		self.result_process.daemon = True
		self.result_process.start()
		
		for i in range(self.agent_proccnt):
			p = ShareEnumProc(self.inQ, self.outQ, self.agent_threadcnt, timeout = self.timeout, pre_check = self.pre_check)
			p.daemon = True
			p.start()
			self.agents.append(p)
		
		logger.info('=== Enumerating shares ===')
		for t in self.hosts:
			self.inQ.put(t)
		
		for a in self.agents:
			for i in range(self.agent_threadcnt):
				self.inQ.put(None)
			
		for a in self.agents:
			a.join()
		
		self.outQ.put(None)
		self.result_process.join()
		