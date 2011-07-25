
#
# Written by Maxim Khitrov (July 2011)
#

from . import Command, load_ids
from .. import DBControl, conf

import argparse

class view(Command):
	"""View message contents.

	This command is used to view the text of messages that will be restored when
	using an ID file (see 'search' and 'restore' commands). All messages are
	printed to the standard output in an arbitrary order.
	"""

	def __call__(self):
		if conf.ids:
			ids = load_ids(conf.ids)
		with DBControl(conf.db) as db:
			if conf.digest:
				body = db.files.read(conf.digest)
				if body is None:
					sys.exit('No such message')
				print(body.decode('ascii', 'replace'))
				return 0
			for id in ids:
				print('\n{:~^80}\n'.format('  {}  '.format(id)))
				print(db.get_body(id).decode('ascii', 'replace'))
		return 0

	@staticmethod
	def build_args(subp):
		mexg = subp.add_mutually_exclusive_group(required=True)
		mexg.add_argument('-d', dest='digest',
			help='message digest to view')
		subp.add_argument('db',
			help='database directory (will be created if it does not exist)')
		mexg.add_argument('ids', nargs='?', type=argparse.FileType(),
			help='file with message ids to view')
