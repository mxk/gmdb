
#
# Written by Maxim Khitrov (July 2011)
#

import sys
if sys.version_info < (3, 2):
	sys.exit('Python 3.2+ required')

try:
	import argparse
	import getpass
	import io
	import locale
	import logging
	import os
	import sqlite3
	import ssl
	import textwrap
except ImportError as exc:
	sys.exit(exc)

# Require SQLite 3.6.19+ for foreign key support
if sqlite3.sqlite_version_info < (3, 6, 19):
	sys.exit('Insufficient sqlite3 version (3.6.19+ required)')

__author__  = 'Maxim Khitrov'
__email__   = 'max@mxcrypt.com'
__version__ = '0.7.0'
__date__    = '2011-07-25'

#
###  I/O encoding  #############################################################
#

def switch_encoding(stream, encoding='UTF-8'):
	mode = getattr(stream, 'mode', None)
	lbuf = stream.line_buffering
	wrap = io.TextIOWrapper(stream.buffer, encoding, line_buffering=lbuf)
	if mode is not None:
		wrap.mode = mode
	return wrap

# Force stdout and stderr to use UTF-8 encoding
sys.stdout = switch_encoding(sys.stdout)
sys.stderr = switch_encoding(sys.stderr)

# Force open() to use UTF-8 encoding by default
locale.getpreferredencoding = lambda do_setlocale=True: 'UTF-8'

#
###  Logging  ##################################################################
#

logging.basicConfig(
	style   = '{',
	format  = '{asctime}  {levelname:8}  {message}',
	datefmt = '%Y-%m-%d %H:%M:%S',
	level   = logging.INFO
)

class Logger(logging.Logger):
	null   = lambda *args, **kwargs: None
	debug1 = null
	debug2 = null
	debug3 = null

class LogRecord(logging.LogRecord):
	def getMessage(self):
		msg = str(self.msg)
		if isinstance(self.args, dict):
			return msg.format(self.args)
		return msg.format(*self.args) if self.args else msg

logging.setLoggerClass(Logger)
logging.setLogRecordFactory(LogRecord)
logging.captureWarnings(True)

log = logging.getLogger('gmdb')

#
###  Main  #####################################################################
#

def main_wrapper():
	try:
		sys.exit(main(sys.argv))
	except KeyboardInterrupt:
		pass
	except Exception:
		log.exception('Unhandled error')
	sys.exit(1)

def main(argv):
	args = parse_args(argv[1:])
	verbose_output(args.verbose)

	# Load password from a file or the terminal
	if getattr(args, 'passwd_file', None):
		read_passwd(args)

	# Load configuration and copy command-line arguments into the conf module
	args.conf = load_conf(args.conf)
	for k, v in vars(args).items():
		setattr(conf, k, v)

	log.debug('Arguments: {}', args)
	cmd = Command(conf.command)
	return cmd()

def parse_args(args):
	argp = argparse.ArgumentParser(description='Gmail Backup Database')
	argp.add_argument('--version', action='version',
		version='%(prog)s ' + __version__)

	# Common options
	common = argparse.ArgumentParser(add_help=False)
	common.add_argument('-c', '--conf', metavar='FILE',
		type=argparse.FileType(), help='configuration file path')
	common.add_argument('-v', dest='verbose', action='count', default=0,
		help='enable verbose output (may be repeated up to 5 times)')

	# IMAP options
	imap = argparse.ArgumentParser(add_help=False)
	imap.add_argument('-s', '--server', metavar='HOST[:PORT]',
		default='imap.gmail.com:993',
		help='server hostname and port [imap.gmail.com:993]')
	imap.add_argument('-t', '--timeout', metavar='SEC', type=int, default=60,
		help='network socket timeout in seconds [60]')
	imap.add_argument('--ssl', action='store_true',
		help='use ssl to connect (on by default when port is 993)')
	imap.add_argument('-V', '--no-verify', action='store_true',
		help="do not verify server's SSL certificate")
	imap.add_argument('-z', '--compress', action='count', default=0,
		help='use link compression (repeat up to 3 times for level={3,6,9})')
	passwd = imap.add_mutually_exclusive_group()
	passwd.add_argument('-p', '--passwd',
		help='account password for plaintext authentication')
	passwd.add_argument('-P', '--passwd-file', metavar='FILE',
		type=argparse.FileType(), help='file containing account password')

	# DB options
	db = argparse.ArgumentParser(add_help=False)
	db.add_argument('-b', '--db-backup', action='store_true',
		help='copy sqlite database file before opening it')

	# Command-specific options
	subp = argp.add_subparsers(title='commands', dest='command')
	for name, cls in sorted(Command.registry.items()):
		parents = [common]
		if cls.uses_imap:
			parents.append(imap)
		if cls.uses_db:
			parents.append(db)
		first, rest = doc_format(cls.__doc__)
		cls.build_args(subp.add_parser(name,
			help            = first.lower().rstrip('.'),
			description     = '{}\n\n{}'.format(first, rest),
			formatter_class = argparse.RawDescriptionHelpFormatter,
			parents         = parents
		))

	return argp.parse_args(args)

def doc_format(doc):
	lines = doc.strip().splitlines()
	first = lines[0].rstrip()
	rest  = textwrap.dedent('\n'.join(lines[2:]))
	return (first, rest)

def verbose_output(level):
	if level:
		log.setLevel(logging.DEBUG)
		imaplib2.debug_level(level)
	for i, method in enumerate(('debug1', 'debug2', 'debug3'), 1):
		target = Logger.debug if i <= level else Logger.null
		setattr(Logger, method, target)

def read_passwd(args):
	fd = args.passwd_file
	args.passwd_file = fd.name
	if fd.isatty():
		args.passwd = getpass.getpass()
		if '\x03' in args.passwd:
			raise KeyboardInterrupt  # Bug fix for python 3.2; see issue 11236
	else:
		args.passwd = fd.readline().rstrip('\r\n')
		if not is_stdin(fd):
			fd.close()

def load_conf(fd=None):
	if fd is None:
		for file in conf.CONF_PATH:
			if os.path.isfile(file):
				fd = open(file)
				break
		else:
			return None
	try:
		ns   = {}
		name = fd.name if is_stdin(fd) else os.path.realpath(fd.name)
		log.debug('Loading configuration file: {}', name)
		exec(fd.read(), ns)
		for k, v in ns.items():
			if hasattr(conf, k) and k.upper() == k:
				setattr(conf, k, v)
		return name
	finally:
		if not is_stdin(fd):
			fd.close()

#
###  GMDB imports  #############################################################
#

from .     import conf, imaplib2
from .imap import IMAP4Control
from .db   import DBControl
from .cmd  import Command
from .util import is_stdin
