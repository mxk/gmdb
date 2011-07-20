
#
# Written by Maxim Khitrov (July 2011)
#

from . import Command

class xyzzy(Command):
	"""Do nothing."""

	uses_imap = True
	uses_db   = True

	def __call__(self):
		print('Nothing happens')
		return 0
