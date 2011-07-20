
#
# Written by Maxim Khitrov (July 2011)
#

from . import Command
from .. import DBControl, conf

empty_keys = ('comp_method', 'digest', 'dir_levels')
all_keys   = ('account', 'retention', 'comp_level') + empty_keys

class config(Command):
	"""Configure database settings.

	The database will be created if it doesn't already exist. The following
	settings may be changed only while the database is empty:

	  comp_method, digest, dir_levels

	Changing --comp-level for a non-empty database is permitted, but this will
	apply only to new messages and will not recompress existing ones.

	The account name should only be changed if it was renamed on the server
	(i.e. the actual message content remained the same).
	"""

	uses_db = True

	def __call__(self):
		width  = max(map(len, all_keys))
		report = '{:>' + str(width) + '}: {}'
		change = report + ' -> {}'

		with DBControl(conf.db) as db:
			if not db.files.empty:
				for k in empty_keys:
					if getattr(conf, k) is not None:
						msg = 'Database is not empty; cannot change {!a}'
						print(msg.format(k))
						return 1

			changed = False
			for k in sorted(all_keys):
				v = getattr(conf, k)
				if v is not None and v != db.conf[k]:
					print(change.format(k, db.conf[k], v))
					db.conf[k] = v
					changed = True
				else:
					print(report.format(k, db.conf[k]))
			if changed:
				db.save_conf(False)
			return 0

	@staticmethod
	def build_args(subp):
		subp.add_argument('-a', '--account', metavar='NAME',
			help='account name (e.g. someone@example.com)')
		subp.add_argument('-m', '--comp-method', choices=('none', 'gzip'),
			help='file compression method [gzip]')
		subp.add_argument('-l', '--comp-level', type=int, choices=range(1, 10),
			help='file compression level [6]')
		subp.add_argument('-i', '--digest', choices=('md5', 'sha1', 'sha256'),
			help='digest algorithm [sha1]')
		subp.add_argument('-d', '--dir-levels', type=int, choices=range(1, 9),
			help='number of directory levels [3]')
		subp.add_argument('-r', '--retention', type=int, metavar='SEC',
			help='time to keep deleted messages in seconds [31536000]')
		subp.add_argument('db',
			help='database directory (will be created if it does not exist)')
