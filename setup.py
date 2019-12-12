from setuptools import setup, find_packages

setup(
	# Application name:
	name="pypykatz",

	# Version number (initial):
	version="0.3.2",

	# Application author details:
	author="Tamas Jos",
	author_email="info@skelsec.com",

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
		'minidump>=0.0.11',
		'minikerberos>=0.0.11',
		'aiowinreg>=0.0.1',
		'msldap>=0.1.1',
		'winsspi>=0.0.3'
	],
	
	entry_points={
		'console_scripts': [
			'pypykatz = pypykatz.__main__:main',
		],
	}
)
