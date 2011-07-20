
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
		ids = load_ids(conf.ids)
		with DBControl(conf.db) as db:
			for id in ids:
				print('\n{:~^80}\n'.format('  {}  '.format(id)))
				print(db.get_body(id).decode('ascii', 'replace'))
		return 0

	@staticmethod
	def build_args(subp):
		subp.add_argument('db',
			help='database directory (will be created if it does not exist)')
		subp.add_argument('ids', metavar='FILE', type=argparse.FileType(),
			help='file with message ids to view')
