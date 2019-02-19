#from builtins import str
__author__ = ("Tamas Jos <info@skelsec.com>")

from pypykatz.pypykatz import pypykatz
from pypykatz.commons.readers.rekall.rekallreader import RekallReader
from pypykatz.commons.common import *
import json
import ntpath
import os

from rekall.plugins.windows import common


class Pypykatz(common.WindowsCommandPlugin):
	"""Extract and decrypt passwords from the LSA Security Service."""
	"""
	IMPORTANT: Using the default viewer on rekall will NOT show you all the info!!!
	Recommendation: Use the out_file and kerberos_dir flags to get all the juicy stuff
	"""

	__name = "pypykatz"

	__args = [
		dict(name="override_timestamp", type="int", required=False,
			 help="The msv dll file timestamp detection fails in some cases."),

		dict(name="out_file", required=False,
			 help="The file name to write."),

		dict(name="kerberos_dir", required=False,
			 help="The file name to write."),

		dict(name="json", required=False, type="bool",
			 help="Write credentials to file in JSON format"),

	]

	table_header = [
		dict(name='LUID', width=6),
		dict(name='Type', width=8),
		dict(name='Sess', width=2),
		dict(name='SID', width=20),
		dict(name='Module', width=7),
		dict(name='Info', width=7),
		dict(name='Domain', width=16),
		dict(name='User', width=16),
		dict(name='SType', width=9),
		dict(name='Secret', width=80)
	]

	def __init__(self, *args, **kwargs):
		super(Pypykatz, self).__init__(*args, **kwargs)

	def collect(self):
		cc = self.session.plugins.cc()
		mimi = pypykatz.go_rekall(self.session, self.plugin_args.override_timestamp)

		if self.plugin_args.out_file and self.plugin_args.json:
			self.session.logging.info('Dumping results to file in JSON format')
			with open(self.plugin_args.out_file, 'w') as f:
				json.dump(mimi, f, cls = UniversalEncoder, indent=4, sort_keys=True)
		
	
		elif self.plugin_args.out_file:
			self.session.logging.info('Dumping results to file')
			with open(self.plugin_args.out_file, 'w') as f:
				f.write('FILE: ======== MEMORY =======\n')
					
				for luid in mimi.logon_sessions:
					f.write('\n'+str(mimi.logon_sessions[luid]))
					
					if len(mimi.orphaned_creds) > 0:
						f.write('\n== Orphaned credentials ==\n')
						for cred in mimi.orphaned_creds:
							f.write(str(cred))
		
		else:
			self.session.logging.info('Dumping results')
			for luid in mimi.logon_sessions:
				for row in mimi.logon_sessions[luid].to_row():
					yield row


		if self.plugin_args.kerberos_dir:
			directory = os.path.abspath(self.plugin_args.kerberos_dir)
			self.session.logging.info('Writing kerberos tickets to %s' % directory)
			base_filename = ntpath.basename('rekall_memory')
			ccache_filename = '%s_%s.ccache' % (base_filename, os.urandom(4).hex()) #to avoid collisions
			mimi.kerberos_ccache.to_file(os.path.join(directory, ccache_filename))
			for luid in mimi.logon_sessions:
				for kcred in mimi.logon_sessions[luid].kerberos_creds:
					for ticket in kcred.tickets:
						ticket.to_kirbi(directory)
								
			for cred in mimi.orphaned_creds:
				if cred.credtype == 'kerberos':
					for ticket in cred.tickets:
						ticket.to_kirbi(directory)
		return