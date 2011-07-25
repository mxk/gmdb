
#
# Written by Maxim Khitrov (July 2011)
#

from ..util import RegisteredType, is_stdin

import logging
import os
import signal
import weakref

__all__ = ['Command', 'SigHandler', 'load_ids']

log = logging.getLogger('gmdb.cmd')

def load_ids(fd):
	if fd is None:
		return None
	try:
		ids  = set()
		col1 = lambda l: l.split(None, 1)[0] if l.strip() else None
		for l, msg_id in enumerate(map(col1, fd), 1):
			if msg_id and msg_id.isdigit():
				msg_id = int(msg_id)
				if 0 <= msg_id <= 2**64 - 1:
					ids.add(msg_id)
					continue
			raise ValueError('invalid id {!a} on line {}'.format(msg_id, l))
		return ids
	finally:
		if not is_stdin(fd):
			fd.close()

class Command(metaclass=RegisteredType):
	"""Base command class."""

	uses_imap = False  # Command requires an IMAP connection
	uses_db   = False  # Command accesses the database

	def __new__(cls, name):
		if cls is Command:
			cls = Command.registry[name]
			if cls.__new__ is not Command.__new__:
				return cls.__new__(cls, name)
		return object.__new__(cls)

	def __call__(self):
		"""Execute command."""
		raise NotImplementedError

	@staticmethod
	def build_args(subp):
		"""Configure argument subparser."""

class SigHandler:
	"""Class for handling system signals."""

	def __init__(self):
		self.abort   = False         # Abort flag
		self.old_sig = None          # Previous signal handlers
		self.status  = lambda: None  # Status weakref during operation

	def __enter__(self):
		"""Register signal handlers."""
		sig = {
			'SIGINT':  self._abort,
			'SIGHUP':  self._abort,
			'SIGTERM': self._abort,
			'SIGINFO': self._status,
			'SIGUSR1': signal.SIG_IGN,
			'SIGUSR2': signal.SIG_IGN
		}
		self.old_sig = {}
		for name, handler in sig.items():
			signum = getattr(signal, name, None)
			if signum is not None:
				self.old_sig[signum] = signal.signal(signum, handler)
		return self

	def __exit__(self, exc_type, exc_val, exc_tb):
		"""Restore original signal handlers."""
		try:
			for signum, handler in self.old_sig.items():
				signal.signal(signum, handler)
		finally:
			self.old_sig = None
			self.status  = lambda: None

	def enable_status(self, status):
		"""Enable status reports."""
		self.status = weakref.ref(status)

	def _abort(self, signum, frame):
		"""Abort operation."""
		if self.abort:
			log.info('Still working...')
		else:
			self.abort = True
			log.warn('Terminating operation, please wait...')

	def _status(self, signum, frame):
		"""Report current status."""
		status = self.status()
		if status:
			status.show()

from . import archive, backup, config, index, labels, restore, search, view

if True:
	from . import shell, xyzzy
