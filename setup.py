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
	packages=find_packages(exclude=["tests*"]),

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
	classifiers=[
		"Programming Language :: Python :: 3.6",
		"License :: OSI Approved :: MIT License",
		"Operating System :: OS Independent",
	],
	install_requires=[
		'unicrypto>=0.0.10,<=0.1.0',
		'minidump>=0.0.21,<=0.1.0',
		'minikerberos>=0.4.1,<=0.5.0',
		'aiowinreg>=0.0.11,<=0.1.0',
		'msldap>=0.5.7,<=0.6.0',
		'winacl>=0.1.9,<=0.2.0',
		'aiosmb>=0.4.8,<=0.5.0',
		'aesedb>=0.1.4,<=0.2.0',
		'tqdm', 
	],
	
	# No more conveinent .exe entry point thanks to some idiot who 
	# used the code without modification in a state-backed trojan.
	# Thank you for runing it for everyone.
	# 
	# 
	entry_points=ep if platform.system().lower() != 'windows' else {}
)
