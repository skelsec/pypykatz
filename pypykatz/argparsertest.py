#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  zpycompletion
#
#  Copyright 2015 Spencer McIntyre <zeroSteiner@gmail.com>
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are
#  met:
#
#  * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above
#    copyright notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
#  * Neither the name of the  nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

import argparse
import contextlib
import datetime
import imp
import os
import pwd
import sys

import jinja2

__all__ = ['make_completion_from_argparse']
__version__ = '1.2'

# script.arguments
# script.author
# script.c_year
# script.name
# script.subparser_cmds
# script.subparsers
# version
ZSH_COMPLETION_TEMPLATE = """\
#compdef {{ script.name }}
# ------------------------------------------------------------------------------
# Copyright (c) {{ script.c_year }} {{ script.author }}
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#   * Neither the name of the project nor the
#     names of its contributors may be used to endorse or promote products
#     derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL ZSH-USERS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# ------------------------------------------------------------------------------
# Description
# -----------
#
#  Completion script for {{ script.name }}.
#
# ------------------------------------------------------------------------------
# Authors
# -------
#
#  * {{ script.author }}
#
# ------------------------------------------------------------------------------
# Generated with zpycompletion v{{ version }}
{% for subparser_cmd in script.subparser_cmds %}

{{ subparser_cmd.name }}() {
  _arguments \\
  {% for line in subparser_cmd.arguments %}
    {{ line }}
  {% endfor %}
}
{% endfor %}

{% for subparser in script.subparsers %}

{{ subparser.name }}() {
  local -a _subparser_cmds
  _subparser_cmds=(
    {% for action in subparser.actions %}
    "{{ action.name }}:{{ action.help }}"
    {% endfor %}
  )

  if (( CURRENT == {{ subparser.position }} )); then
    _describe "commands" _subparser_cmds
  else
    local curcontext="$curcontext"
    cmd="${${_subparser_cmds[(r)$words[{{ subparser.position }}]:*]%%:*}}"
    if (( $#cmd )); then
      if (( $+functions[{{ subparser.name }}_cmd_$cmd] )); then
        {% if subparser.position > 1 -%}
        (( CURRENT -= {{ subparser.position - 1 }} ))
        shift {{ subparser.position - 1 }} words
        {% endif -%}
        {{ subparser.name }}_cmd_$cmd CURRENT
      else
        _files
      fi
    else
      _message "unknown command: $words[{{ subparser.position }}]"
    fi
  fi
}
{% endfor %}
_arguments \\
{% for line in script.arguments %}
  {{ line }}
{% endfor %}
"""

def _actions_sort(action):
	if len(action.option_strings):
		return sorted(action.option_strings)[-1]
	return ''

def _argument_action(action):
	zarg_action = ''
	if action.choices:
		zarg_action = ':(' + ' '.join(action.choices) + ')'
	elif isinstance(action.type, argparse.FileType):
		zarg_action = ':_files'
	return zarg_action

class _ZshCompletion(object):
	def __init__(self, parser):
		self.parser = parser
		self.arguments = []
		self.subparsers = []
		self.subparser_cmds = []
		actions = sorted(self.parser._actions, key=_actions_sort)
		self.arguments = self._parse_actions(actions)

	def _parse_actions(self, actions, subparser_name=None):
		lines = []
		subparser = None
		positional = 1
		for action in actions:
			if isinstance(action, argparse._SubParsersAction):
				subparser = (action, positional)
				continue
			if isinstance(action, argparse._HelpAction):
				lines.append("{-h,--help}\"[show help text]\"")
				continue

			if len(action.option_strings) == 0: # positional
				if isinstance(action.nargs, int) and action.nargs > 1:
					for _ in range(positional, (positional + action.nargs)):
						lines.append("\"{0}::{1}{2}\"".format(positional, action.dest, _argument_action(action)))
						positional += 1
					continue
				elif action.nargs in (argparse.REMAINDER, '*', '+'):
					line = '"*'
				elif action.nargs in (None, 1, '?'):
					line = '"' + str(positional)
					positional += 1
				line += ':' + action.dest
			else:
				if len(action.option_strings) == 1:
					options = '"' + action.option_strings[0]
				else:
					options = '{' + ','.join(action.option_strings) + '}"'
				if isinstance(action, argparse._AppendAction):
					line = '"*"' + options + "[{0}]:{1}".format(action.help, action.dest.replace('_', ' '))
				elif isinstance(action, argparse._StoreAction):
					line = options + "[{0}]:{1}".format(action.help, action.dest.replace('_', ' '))
				elif isinstance(action, argparse._VersionAction):
					line = options + '[show version information]'
				elif isinstance(action, argparse._StoreConstAction):
					line = options + '[' + action.help + ']'
				else:
					continue
			line += _argument_action(action) + '"'
			lines.append(line)

		if subparser:
			subparser, position = subparser
			subp_actions = map(lambda a: dict(name=a.dest, help=a.help), subparser._choices_actions)
			subp_dest = ('action' if subparser.dest == argparse.SUPPRESS else subparser.dest)
			subp_name = (subparser_name or '_subparser') + '_' + subp_dest
			self.subparsers.append(dict(name=subp_name, position=position, actions=subp_actions))

			lines.append("\"*::{0}:{1}\"".format(subp_dest, subp_name))
			for key, value in subparser._name_parser_map.items():
				subp_cmd_name = "{0}_cmd_{1}".format(subp_name, key)
				subp_cmd_arguments = self._parse_actions(value._actions, subparser_name=subp_name)
				self.subparser_cmds.append(dict(name=subp_cmd_name, arguments=subp_cmd_arguments))

		for i in range(len(lines) - 1):
			lines[i] = lines[i] + ' \\'
		return lines

def make_completion_from_argparse(parser, destination=None, input_prompt=True):
	"""
	Create a zsh completion file from a :py:class:`argparse.ArgumentParser`
	instance.

	:param parser: The parser instance to build completions for.
	:type parser: :py:class:`argparse.ArgumentParser`
	:param bool input_prompt: Whether to prompt for user input or not.
	"""
	script = {}
	#script['author'] = pwd.getpwuid(os.getuid()).pw_gecos
	#if input_prompt:
	#	script['author'] = input("[?] author ({0}): ".format(script['author'])) or script['author']
	#script['c_year'] = datetime.date.today().year
	#if input_prompt:
	#	script['c_year'] = input("[?] copyright year ({0}): ".format(script['c_year'])) or script['c_year']
	#script['name'] = parser.prog
	#if input_prompt:
	#	script['name'] = input("[?] script name ({0}): ".format(script['name'])) or script['name']

	zsh_comp = _ZshCompletion(parser)
	script['arguments'] = zsh_comp.arguments
	script['subparsers'] = zsh_comp.subparsers
	script['subparser_cmds'] = zsh_comp.subparser_cmds

	return script
	#env = jinja2.Environment(trim_blocks=True)
	#template = env.from_string(ZSH_COMPLETION_TEMPLATE)
	#destination = destination or '_' + script['name']
	#with open(destination, 'w') as file_h:
	#	file_h.write(template.render(script=script, version=__version__))
	#print('[*] completion saved as: ' + destination)

class _FakeArgparse(object):
	def __init__(self):
		self.parser = None

	def __getattr__(self, name):
		if name == 'ArgumentParser':
			return self._hook
		return getattr(argparse, name)

	def _hook(self, *args, **kwargs):
		self.parser = argparse.ArgumentParser(*args, **kwargs)
		return self.parser

@contextlib.contextmanager
def _muted_std_streams():
	stdout = sys.stdout
	stderr = sys.stderr
	sys.stdout = open(os.devnull, 'w')
	sys.stderr = open(os.devnull, 'w')
	try:
		yield
	except Exception:
		raise
	finally:
		sys.stdout = stdout
		sys.stderr = stderr

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('-m', '--method', dest='target_function', default='main', help='the function which creates the ArgumentParser instance')
	parser.add_argument('-o', '--output', dest='output', help='the path to write the completion file to')
	parser.add_argument('--no-prompt', dest='input_prompt', default=True, action='store_false', help='do not prompt for input')
	parser.add_argument('script', help='the python script to load from')
	arguments = parser.parse_args()

	script = os.path.abspath(arguments.script)
	if not os.path.isfile(script):
		print('[-] invalid script file: ' + script)
		return
	script_path, script_name = os.path.split(script)

	sys.path.append(script_path)
	script_import_name = script_name
	if script_import_name.endswith('.py'):
		script_import_name = script_name[:-3]

	sys.dont_write_bytecode = True
	sys.modules['argparse'] = _FakeArgparse()
	print('[*] importing: ' + script_import_name)
	try:
		module = imp.load_source(script_import_name, script)
	except SyntaxError:
		print('[!] failed to import the python file')
		return

	if not hasattr(module, arguments.target_function):
		print("[-] the specified script has no {0}() function".format(arguments.target_function))
		print('[-] can not automatically get the parser instance')
		return

	sys.argv = [script_name, '--help']
	try:
		with _muted_std_streams():
			getattr(module, arguments.target_function)()
	except SystemExit:
		pass
	if not sys.modules['argparse'].parser:
		print("[-] no parser was created in {0}.{1}()".format(script_name, arguments.target_function))
		return
	make_completion_from_argparse(sys.modules['argparse'].parser, destination=arguments.output, input_prompt=arguments.input_prompt)

if __name__ == '__main__':
	main()