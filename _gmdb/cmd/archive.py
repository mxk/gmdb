
#
# Written by Maxim Khitrov (July 2011)
#

from io import BytesIO
from . import Command
from .. import DBControl, conf

import argparse
import os
import sys
import tarfile
import zipfile

class archive(Command):
	"""Compress all messages into a single flat archive.

	Running this command will create a new zip, gz, or bz2 archive containing
	every message in its original (uncompressed) format. The SQLite database is
	not included in the archive.
	"""

	def __call__(self):
		exts = {
			'zip': (self._zip_open, self._zip_write),
			'gz':  (self._gz_open,  self._tar_write),
			'bz2': (self._bz2_open, self._tar_write)
		}
		for ext in ('gzip', 'tgz'):
			exts[ext] = exts['gz']
		for ext in ('bzip2', 'tbz', 'tbz2'):
			exts[ext] = exts['bz2']

		# If writing to stdout, switch to binary mode
		is_stdout = conf.dest.fileno() == sys.stdout.fileno()
		if is_stdout:
			conf.dest = sys.stdout.buffer

		if conf.format:
			ext = conf.format
		else:
			if is_stdout:
				sys.exit('format must be specified')
			ext = os.path.splitext(conf.dest.name)[1].lstrip('.')
			if ext not in exts:
				sys.exit('unrecognized file extension: {}'.format(ext))
		m_open, m_write = exts[ext]

		with DBControl(conf.db) as db:
			files = db.files
			dest  = m_open(conf.dest)
			try:
				for digest in files:
					m_write(dest, digest, files.read(digest))
			finally:
				dest.close()
		return 0

	@staticmethod
	def build_args(subp):
		subp.add_argument('-f', '--format', choices=['zip', 'gz', 'bz2'],
			help='output format (determined from the file name by default)')
		subp.add_argument('-l', '--level', type=int, choices=range(1, 10),
			default=6,
			help='compression level for gz and bz2 formats (default = 6)')
		subp.add_argument('db',
			help='database directory (will be created if it does not exist)')
		subp.add_argument('dest', type=argparse.FileType('wb', 65536),
			help='destination file name or stdout')

	def _zip_open(self, fd):
		return zipfile.ZipFile(fd, 'w', zipfile.ZIP_DEFLATED, True)

	def _zip_write(self, arc, digest, data):
		arc.writestr(digest, data)

	def _gz_open(self, fd):
		return tarfile.open(None, 'w:gz', fd, compresslevel=conf.level)

	def _bz2_open(self, fd):
		return tarfile.open(None, 'w:bz2', fd, compresslevel=conf.level)

	def _tar_write(self, arc, digest, data):
		info = tarfile.TarInfo(digest)
		info.size = len(data)
		arc.addfile(info, BytesIO(data))
