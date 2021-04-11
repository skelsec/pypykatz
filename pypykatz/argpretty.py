
import pprint
from .argparsertest import make_completion_from_argparse


def argpretty(parser):
	
	#print(1)
	#input(pprint.pprint(parser.__dict__))
	#print(2)
	#input(pprint.pprint(parser.__dict__['_actions']))

	x = make_completion_from_argparse(parser)
	pprint.pprint(x['subparsers'])
	
	for key in x:
		print(key)
		
	input()
	for rd in x['subparser_cmds']:
		print(rd['name'])
	
	
	input()