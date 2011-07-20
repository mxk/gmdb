
#
# Written by Maxim Khitrov (July 2011)
#

from . import Command
from .. import DBControl, conf
from ..db import uint64

import time

# TODO: Add an option to update thr_id during backup (test performance first)

class search(Command):
	"""Search message index.

	This command is used to create a message ID file, which may them be passed
	to the --ids (-I) restore command option. For example:

	  $ gmdb search <database> 'some terms from:someone' > ids
	  $ gmdb restore -I ids <account>

	Search is implemented by passing the query parameter to the SQLite FTS
	'MATCH' expression. Simple queries, such as the one above, may be
	constructed without detailed knowledge of how FTS works. For more advanced
	use, please read the official FTS module documentation:

	  http://www.sqlite.org/fts3.html

	The FTS table indexes 'from', 'to', 'subject', and 'body' of each message.
	'Body' is restricted to the first text/plain part of the message. 'To' is a
	combination of 'To', 'CC', 'BCC', and 'Resent-{To,CC,BCC}' headers. These
	four columns may be used in the query parameter to restrict search. The
	previous example will only find messages where the 'from' column contains
	the token 'someone', and tokens 'some' and 'terms' are present anywhere else
	in the indexed parts of the message.

	The search may also be restricted by date and labels. Specifying --before
	(-b) and/or --after (-a) will only return messages with the Date header that
	matches the set limit. Each date (YYYY-MM-DD) is taken to mean 12:00am
	(midnight) that day. Labels can be restricted with the --label (-l)
	parameter, which may be repeated. A message will match if at least one of
	its labels is listed on the command line. For example, the following query
	will match all messages labeled Work or IT that were received 2011-07-18:

	  $ gmdb search -a 2011-07-18 -b 2011-07-19 -l work -l it ''

	By default, the command returns the IDs of individual messages that match
	your search criteria. Gmail, on the other hand, returns complete
	conversations in the search results. To mimic this behavior, specify the
	--threads (-t) option, which will return complete conversations with at
	least one matching message.
	"""

	def __call__(self):
		threaded  = conf.threads
		sql, args = self._build_query(threaded)

		with DBControl(conf.db) as db:
			if not db.attach_index():
				return 1

			lbl_conv  = lambda lbls: set(map(str.lower, lbls))
			lbl_match = lambda msg_id: labels & lbl_conv(db.get_labels(msg_id))
			labels    = lbl_conv(conf.label) if conf.label else None
			thr_prev  = None
			thr_num   = 0

			for msg_id, thr_id, digest in db.cn.execute(sql, args):
				msg_id = uint64(msg_id)
				if not threaded:
					if not labels or lbl_match(msg_id):
						print(msg_id, digest)
					continue
				if thr_id != thr_prev:
					thr_prev  = thr_id
					thr_num  += 1
					thr_match = False
					thr_queue = []
				elif thr_match and not thr_queue:
					print('{} {}  # Thread {}'.format(msg_id, digest, thr_num))
					continue
				thr_queue.append((msg_id, digest))
				if labels and not thr_match and not lbl_match(msg_id):
					continue
				for msg_id, digest in thr_queue:
					print('{} {}  # Thread {}'.format(msg_id, digest, thr_num))
				thr_match = True
				thr_queue = []
			return 0

	@staticmethod
	def build_args(subp):
		subp.add_argument('-a', '--after', metavar='YYYY-MM-DD',
			help='only search messages newer than the given date (midnight)')
		subp.add_argument('-b', '--before', metavar='YYYY-MM-DD',
			help='only search messages older than the given date (midnight)')
		subp.add_argument('-t', '--threads', action='store_true',
			help='find complete threads rather than individual messages')
		subp.add_argument('-l', '--label', action='append',
			help='restrict search to the specified label(s) (may be repeated)')
		subp.add_argument('db',
			help='database directory (will be created if it does not exist)')
		subp.add_argument('query', help='full-text search query')

	def _build_query(self, threaded):
		date = lambda s: time.mktime(time.strptime(s, '%Y-%m-%d'))
		sql  = []
		args = {}

		if threaded:
			sql.append('''
				SELECT msg_id, thr_id, digest FROM msg, file USING (file_id)
				WHERE thr_id IN (
					SELECT DISTINCT thr_id
			''')
		else:
			sql.append('SELECT msg_id, NULL AS thr_id, digest')

		sql.append('''
			FROM fts
				JOIN map  USING (docid)
				JOIN file USING (digest)
				JOIN msg  USING (file_id)
			WHERE 1=1
		''')

		if conf.query:
			sql.append('AND fts MATCH :fts')
			args['fts'] = conf.query
		if conf.after:
			sql.append('AND date >= :after')
			args['after'] = date(conf.after)
		if conf.before:
			sql.append('AND date < :before')
			args['before'] = date(conf.before)
		if threaded:
			sql.append(') ORDER BY thr_id')

		return (' '.join(sql), args)
