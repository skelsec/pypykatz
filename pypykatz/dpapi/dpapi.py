import os

from pypykatz import logger

class DPAPI:
	def __init__(self):
		pass
	
	@staticmethod
	def list_masterkeys():
		logger.debug('Searching for MasterKey files...')
		appdata = os.environ.get('APPDATA')
		'%APPDATA%\Microsoft\Protect\%SID%'
		'%SYSTEMDIR%\Microsoft\Protect'