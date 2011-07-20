
#
# Written by Maxim Khitrov (July 2011)
#

from . import Command
from .. import DBControl, conf

class index(Command):
	"""Update message index.

	This command creates the full-text search database, which is used by the
	'search' command. The indexing operation requires a significant amount of
	disk space and may take several hours to complete, depending on your
	hardware. In testing, a backup of 350,000 messages, 9 KB in size on average,
	required ~1.5 hours to index on an Atom D525 CPU and 1.2 GB of disk space.
	"""

	def __call__(self):
		with DBControl(conf.db) as db:
			db.attach_index(False)
			return 0

	@staticmethod
	def build_args(subp):
		subp.add_argument('db',
			help='database directory (will be created if it does not exist)')
