
#
# Written by Maxim Khitrov (July 2011)
#

from collections import defaultdict, deque, OrderedDict
from .imaplib2 import qstr

import logging
import os
import re
import sys
import time

__all__ = [
	'defaultdict', 'deque', 'OrderedDict', 'qstr', 'unixtime', 'walltime',
	'unqstr', 'qstr_split', 'bytes_fmt', 'ema', 'is_stdin', 'LockFile',
	'RegisteredType'
]

log = logging.getLogger('gmdb.util')

# Absolute and relative timing
unixtime = lambda: int(time.time())
walltime = time.clock if os.name == 'nt' else time.time

# Initialize time.clock on Windows
walltime()

# Quoted string format
_qstr = re.compile(r'"(?:[^\\"]|\\\\|\\")*"')

def unqstr(s):
	"""Unquote a quoted string (inverse of qstr)."""
	return s[1:-1].replace('\\"', '"').replace('\\\\', '\\')

def qstr_split(s):
	"""Split a string containing zero or more quoted strings."""
	return list(map(unqstr, _qstr.findall(s)))

def bytes_fmt(value, precision=2):
	"""Represent bytes value in a human-readable format."""
	for units in ('B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'):
		if value < 1024 or units == 'YB':
			if units != 'B' or isinstance(value, float):  # float = rate (B/s)
				value = round(value, precision)
			return '{} {}'.format(value, units)
		value /= 1024

def ema(avg, sample, weight=0.1):
	"""Exponential moving average."""
	return sample if avg is None else (avg * (1.0 - weight)) + (sample * weight)

def is_stdin(stream):
	"""Check if the given stream is stdin."""
	return stream.fileno() == sys.__stdin__.fileno()

class LockFile:
	"""Class for controlling access to a file system resource."""

	def __init__(self, file, mode=0o644):
		self.file  = os.path.realpath(file)
		self.mode  = mode
		self.flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
		self.fd    = None

		# Windows-specific flags
		if os.name == 'nt':
			self.flags |= os.O_TEMPORARY | os.O_NOINHERIT

	def __enter__(self):
		self.create()
		return self

	def __exit__(self, exc_type, exc_val, exc_tb):
		self.remove()

	def create(self):
		if self.fd is not None:
			return
		pid = str(os.getpid())
		try:
			self.fd = os.open(self.file, self.flags, self.mode)
			os.write(self.fd, pid.encode('ascii') + b'\n')
			log.debug('Lock file created [pid={}]', pid)
		except Exception:
			log.error('Failed to create lock file: {}', self.file)
			self.remove()
			raise

	def remove(self):
		if self.fd is None:
			return
		try:
			# Windows automatically deletes the file on close (O_TEMPORARY)
			if os.name != 'nt':
				os.unlink(self.file)
			os.close(self.fd)
			log.debug('Lock file removed')
		except Exception:
			log.exception('Failed to remove lock file')
			# Do not re-raise
		finally:
			self.fd = None

class RegisteredType(type):
	"""Metaclass used to automatically register classes on definition."""

	_registry_key = '__name__'

	def __new__(mcs, name, bases, attrs):
		cls = type.__new__(mcs, name, bases, attrs)
		cls._register()
		return cls

	def _register(cls):
		if hasattr(cls, 'registry'):
			key = getattr(cls, cls._registry_key)
			if key in cls.registry:
				raise ValueError("duplicate registration for '{}'".format(key))
			cls.registry[key] = cls
		else:
			cls.registry = {}
