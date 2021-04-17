from setuptools import setup, find_packages
import re
import platform

VERSIONFILE="pypykatz/_version.py"
verstrline = open(VERSIONFILE, "rt").read()
VSRE = r"^__version__ = ['\"]([^'\"]*)['\"]"
mo = re.search(VSRE, verstrline, re.M)
if mo:
    verstr = mo.group(1)
else:
    raise RuntimeError("Unable to find version string in %s." % (VERSIONFILE,))

ep = {
	'console_scripts': [
			'pypykatz = pypykatz.__main__:main',
		],
	}

setup(
	# Application name:
	name="pypykatz",

	# Version number (initial):
	version=verstr,

	# Application author details:
	author="Tamas Jos",
	author_email="info@skelsecprojects.com",

	# Packages
	packages=find_packages(),

	# Include additional files into the package
	include_package_data=True,


	# Details
	url="https://github.com/skelsec/pypykatz",

	zip_safe = True,
	#
	# license="LICENSE.txt",
	description="Python implementation of Mimikatz",

	# long_description=open("README.txt").read(),
	python_requires='>=3.6',
	classifiers=(
		"Programming Language :: Python :: 3.6",
		"License :: OSI Approved :: MIT License",
		"Operating System :: OS Independent",
	),
	install_requires=[
		'minidump>=0.0.17',
		'minikerberos>=0.2.11',
		'aiowinreg>=0.0.4',
		'msldap>=0.3.29',
		'winacl>=0.1.1',
		'aiosmb>=0.2.41',
	],
	
	# No more conveinent .exe entry point thanks to some idiot who 
	# used the code without modification in a state-backed trojan.
	# Thank you for runing it for everyone.
	# 
	# 
	entry_points=ep if platform.system().lower() != 'windows' else {}
)
