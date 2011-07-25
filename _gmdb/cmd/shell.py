
#
# Written by Maxim Khitrov (2011)
#

from pprint import PrettyPrinter

from . import Command
from .. import DBControl, IMAP4Control, conf, imaplib2
from ..util import *

import codeop
import logging
import os
import sys

try:
	import readline
except ImportError:
	readline = None

# Names of all registered IMAP commands
_imap_cmds = set(imaplib2.IMAP4Command.registry)

def auth():
	imap._init(imap.cn)
	log.info('Authentication successful!')
	del globals()['auth']

class shell(Command):
	"""Connect to the IMAP server and go into interactive mode.

	This command is used for testing and debugging IMAP communications. After
	connecting to the server, it performs the same type of authentication as for
	backup and restore operations. If authentication is successful, the user is
	presented with an interactive prompt, which permits the execution of python
	or raw IMAP commands.

	Verbose output should be enabled via the repeatable '-v' option.
	"""

	uses_imap = True

	def __call__(self):
		global log, imap

		log = logging.getLogger('gmdb.cmd.shell')
		self.comp = codeop.CommandCompiler()

		sys.ps1 = getattr(sys, 'ps1', '>>> ')
		sys.ps2 = getattr(sys, 'ps2', '... ')

		if readline and conf.hist and os.path.isfile(conf.hist):
			readline.read_history_file(conf.hist)

		with IMAP4Control(False) as imap:
			print("\nYou may run now Python or IMAP commands:")
			print(">>> print('hello, world')")
			print(">>> SELECT INBOX\n")
			print("Run 'auth()' to perform normal authentication steps.")
			print("Press <Ctrl-C> once to cancel the current command.")
			print("Press <Ctrl-C> twice to exit (or type 'quit' or 'exit').\n")
			try:
				self._cmd_loop()
			finally:
				if readline and conf.hist:
					readline.write_history_file(conf.hist)

	@staticmethod
	def build_args(subp):
		subp.add_argument('-i', '--hist', metavar='FILE',
			help='read and write the specified history file')
		subp.add_argument('account',
			help='login account (e.g. someuser@example.com)')

	def _cmd_loop(self):
		_fmt   = PrettyPrinter()
		_kbint = False

		cn = imap.cn
		while cn.state != 'logout':
			try:
				# Read command
				_line  = input(sys.ps1).rstrip()
				_ret   = None
				_kbint = False
				if not _line:
					continue
				if _line in ('quit', 'exit'):
					break

				# Execute command
				if _line.startswith('UID '):
					_parts = _line.split(None, 2)[1:]
					_parts[0] = 'UID ' + _parts[0]
				else:
					_parts = _line.split(None, 1)
				if _parts[0] in _imap_cmds:
					cn(*_parts).wait()
				else:
					_co = self._compile(_line)
					while _co is None:
						_line += '\n' + input(sys.ps2)
						_co = self._compile(_line)
					_ret = eval(_co)

				# Print results
				if isinstance(_ret, (dict, list, tuple, set, frozenset)):
					print(_fmt.pformat(_ret))
				elif _ret is not None:
					print(_ret)

			except KeyboardInterrupt:
				print('^C')
				if _kbint:
					break
				_kbint = True

			except Exception:
				log.exception('General error')

	def _compile(self, source):
		try:
			return self.comp(source, symbol='eval')
		except SyntaxError:
			pass
		return self.comp(source)
