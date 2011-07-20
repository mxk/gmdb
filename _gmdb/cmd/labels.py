
#
# Written by Maxim Khitrov (July 2011)
#

from . import Command
from .. import DBControl, conf

class labels(Command):
	"""List all unique message labels stored in the database."""

	def __call__(self):
		with DBControl(conf.db) as db:
			for lbl in sorted(db.get_labels(), key=str.upper):
				print(lbl)
			return 0

	@staticmethod
	def build_args(subp):
		subp.add_argument('db',
			help='database directory (will be created if it does not exist)')
