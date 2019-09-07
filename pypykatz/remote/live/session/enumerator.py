
import json
from threading import Thread
from multiprocessing import Process, Queue
from pypykatz import logger

from pypykatz.commons.winapi.local.function_defs.netapi32 import NetSessionEnum
from pypykatz.remote.live.common.common import is_port_up
from pypykatz.commons.common import UniversalEncoder


class SessMonThread(Thread):
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
				for share in NetSessionEnum(target, level=1):
					self.outQ.put((target, share))
			except Exception as e:
				logger.debug('SessionMonitor error: %s' % str(e))
				continue
		
class SessMonProc(Process):
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
			t = SessMonThread(self.inQ, self.outQ, timeout = self.timeout, pre_check = self.pre_check)
			t.daemon = True
			t.start()
			self.threads.append(t)			
		for t in self.threads:
			t.join()
		
class SMResProc(Process):
	def __init__(self, outQ, out_file = None, to_json = False):
		Process.__init__(self)
		self.outQ = outQ
		self.results = {}
		self.out_file = out_file
		self.to_json = to_json
		
	def setup(self):
		return
	
	def run(self):
		self.setup()
		while True:
			result = self.outQ.get()
			if not result:
				break
			
			target, session = result
			if self.to_json is True:
				if target not in self.results:
					self.results[target] = []
				self.results[target].append(session.to_dict())
			
			else:
				ip = session.computername.replace('\\\\','')
				result = '%s %s %s' % (target, ip, session.username)
				if self.out_file is not None:
					if target not in self.results:
						self.results[target] = []
					self.results[target].append(result)
				else:
					print(result)
		
		if self.out_file is None and self.to_json is False:
			return
		
		logger.info('Writing results...')		
		if self.out_file is not None:
			with open(self.out_file,'w', newline = '') as f:
				if self.to_json is True:
					f.write(json.dumps(self.results, cls = UniversalEncoder, indent=4, sort_keys=True))
				else:
					for target in self.results:
						for res in self.results[target]:
							f.write( '%s %s\r\n' % (target, res))
		else:
			print(json.dumps(self.results, cls = UniversalEncoder, indent=4, sort_keys=True))
			

class SessionMonitor:
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
		self.out_file = None
		self.to_json = False
		
		
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
		self.result_process = SMResProc(self.outQ, out_file = self.out_file, to_json = self.to_json)
		self.result_process.daemon = True
		self.result_process.start()
		
		for i in range(self.agent_proccnt):
			p = SessMonProc(self.inQ, self.outQ, self.agent_threadcnt, timeout = self.timeout, pre_check = self.pre_check)
			p.daemon = True
			p.start()
			self.agents.append(p)
		
		logger.info('=== Polling sessions ===')
		for t in self.hosts:
			self.inQ.put(t)
		
		for a in self.agents:
			for i in range(self.agent_threadcnt):
				self.inQ.put(None)
			
		for a in self.agents:
			a.join()
		
		self.outQ.put(None)
		self.result_process.join()
		