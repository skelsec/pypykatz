from setuptools import setup, find_packages
import re

VERSIONFILE="pypykatz/_version.py"
verstrline = open(VERSIONFILE, "rt").read()
VSRE = r"^__version__ = ['\"]([^'\"]*)['\"]"
mo = re.search(VSRE, verstrline, re.M)
if mo:
    verstr = mo.group(1)
else:
    raise RuntimeError("Unable to find version string in %s." % (VERSIONFILE,))

setup(
	# Application name:
	name="pypykatz",

	# Version number (initial):
	version=verstr,

	# Application author details:
	author="Tamas Jos",
	author_email="skelsecprojects@gmail.com",

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
		'minidump>=0.0.12',
		'minikerberos>=0.2.1',
		'aiowinreg>=0.0.3',
		'msldap>=0.2.13',
		'winsspi>=0.0.9'
	],
	
	entry_points={
		'console_scripts': [
			'pypykatz = pypykatz.__main__:main',
		],
	}
)
