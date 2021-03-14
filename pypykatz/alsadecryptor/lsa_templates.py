#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#


from pypykatz.commons.common import KatzSystemArchitecture, WindowsMinBuild
from pypykatz.alsadecryptor.lsa_template_nt5 import LsaTemplate_NT5
from pypykatz.alsadecryptor.lsa_template_nt6 import LsaTemplate_NT6

class LsaTemplate:
	def __init__(self):
		pass


	@staticmethod
	def get_template_brute(sysinfo):
		if sysinfo.architecture == KatzSystemArchitecture.X86:
			if sysinfo.buildnumber < WindowsMinBuild.WIN_VISTA.value:
				return LsaTemplate_NT5.get_template_brute(sysinfo)
			else:
				return LsaTemplate_NT6.get_template_brute(sysinfo)

		elif sysinfo.architecture == KatzSystemArchitecture.X64:
			if sysinfo.buildnumber < WindowsMinBuild.WIN_VISTA.value:
				return LsaTemplate_NT5.get_template_brute(sysinfo)
			else:
				return LsaTemplate_NT6.get_template_brute(sysinfo)

	
	@staticmethod
	def get_template(sysinfo):		
		if sysinfo.architecture == KatzSystemArchitecture.X86:
			if sysinfo.buildnumber < WindowsMinBuild.WIN_VISTA.value:
				return LsaTemplate_NT5.get_template(sysinfo)
			else:
				return LsaTemplate_NT6.get_template(sysinfo)

		elif sysinfo.architecture == KatzSystemArchitecture.X64:
			if sysinfo.buildnumber < WindowsMinBuild.WIN_VISTA.value:
				return LsaTemplate_NT5.get_template(sysinfo)
			else:
				return LsaTemplate_NT6.get_template(sysinfo)