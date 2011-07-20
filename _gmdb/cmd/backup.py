
#
# Written by Maxim Khitrov (July 2011)
#

from . import Command, SigHandler
from .. import IMAP4Control, DBControl, conf
from ..util import *

import logging
import socket

def store(op, queue):
	count = len(queue)
	while queue:
		op.store(queue.popleft())
	return count

def check_abort(op):
	if sig.abort:
		op.commit()
		raise KeyboardInterrupt

class backup(Command):
	"""Perform account backup.

	A complete copy of each message on the server is saved to the local disk. By
	default, messages in Spam and Trash are excluded from the backup, but may be
	included by using --spam and --trash options. Messages may be filtered using
	the Gmail search syntax to reduce the size of the backup. For help on
	creating search criteria see:

	  http://mail.google.com/support/bin/answer.py?answer=7190

	The argument to --filter (-f) must in the same format as shown in the Gmail
	search box AFTER executing the search. For example, if Gmail changes the
	search string 'label:a/b/c' to 'label:a-b-c' (which it does), you should
	specify --filter 'label:a-b-c' on the command line.
	"""

	uses_imap = True
	uses_db   = True

	def __call__(self):
		global log, sig

		log = logging.getLogger('gmdb.cmd.backup')
		err = log.exception if conf.verbose else log.error

		source = ['allmail']
		if conf.trash:
			source.append('trash')
		if conf.spam:
			source.append('spam')
		if conf.db is None:
			conf.db = conf.account
		try:
			with SigHandler() as sig, DBControl(conf.db) as db:
				log.info('Account: {!a}', conf.account)
				op = db.begin_op('backup')
				with IMAP4Control() as self.imap:
					if self.imap.srv_type != 'gmail':
						raise RuntimeError('not a gmail server')
					for mbox in source:
						self._backup(sig, op, mbox)
						check_abort(op)
					op.finish()
					return 0
		except KeyboardInterrupt:
			err('Backup interrupted by user')
		except socket.timeout:
			err('Connection timeout')
		except Exception as exc:
			msg = str(exc)
			err(msg[:1].upper() + msg[1:])
		return 1

	@staticmethod
	def build_args(subp):
		subp.add_argument('-d', '--db', metavar='DIR',
			help='database directory (defaults to account name)')
		subp.add_argument('-f', '--filter', metavar='CRITERIA',
			help='message filter criteria (gmail search syntax)')
		subp.add_argument('-L', '--no-labels', action='store_true',
			help='do not backup message labels (for better performance)')
		subp.add_argument('--spam', action='store_true',
			help='back up messages in spam')
		subp.add_argument('--trash', action='store_true',
			help='back up messages in trash')
		subp.add_argument('account',
			help='login account (e.g. someuser@example.com)')

	def _backup(self, sig, op, mbox):
		exists = self.imap.select(self.imap.find_mbox(mbox))
		if not exists:
			log.info('No messages found in {!a}', mbox)
			return
		check_abort(op)
		log.info('Scanning {} message(s) in {!a}...', exists, mbox)

		# Add an extra label to each message depending on the location
		add_lbl = '^' + mbox.capitalize() if mbox in ('spam', 'trash') else None

		queue  = {}
		status = Status(op, self.imap, queue)
		sig.enable_status(status)

		n = 0
		for n, msg in self.imap.scan(conf.filter, not conf.no_labels, True):
			if n is None:
				self._checkpoint(op, queue, status)
			else:
				if add_lbl:
					msg['labels'].append(add_lbl)
				if msg['msg_id'] in op.db:
					op.update(msg)
				else:
					queue[msg['uid']] = msg
				status.update(n)
			check_abort(op)
		if n is not None:
			self._checkpoint(op, queue, status)
		status.done()

	def _checkpoint(self, op, queue, status):
		if queue:
			if conf.verbose >= 2:
				msize = lambda msg: msg['size']
				count = len(queue)
				bytes = bytes_fmt(sum(map(msize, queue.values())))
				log.debug2('Downloading {} messages (~{})...', count, bytes)

			buf_queue = deque()  # Downloaded message queue
			buf_bytes = 0        # Size of downloaded message queue

			status.dl_begin()
			for msg in self.imap.fetch_body(queue):
				del queue[msg['uid']]
				buf_queue.append(msg)
				buf_bytes += len(msg['body'])

				# Write messages to disk in groups of DL_BUFFER_LIMIT bytes
				if buf_bytes >= conf.DL_BUFFER_LIMIT:
					status.dl_done(store(op, buf_queue), buf_bytes)
					buf_bytes = 0

				check_abort(op)
				status.dl_begin()

			if buf_queue:
				status.dl_done(store(op, buf_queue), buf_bytes)
			if queue:
				status.dl_failed(len(queue))
			queue.clear()
		else:
			log.debug2('Checkpoint (nothing to download)...')
		op.commit()
		op.begin()

class Status:
	def __init__(self, op, imap, queue):
		total = imap.mbox['exists']
		log.info('Progress: 0 / {} (0%)', total)

		self.op       = op     # Current database operation
		self.imap     = imap   # IMAP4 connection
		self.total    = total  # Total number of messages in the mailbox
		self.next_n   = 1      # Next expected message number
		self.scanned  = 0      # Number of messages scanned
		self.skipped  = 0      # Number of messages skipped
		self.dl_queue = queue  # Queue of messages waiting to be downloaded
		self.dl_count = 0      # Number of new messages downloaded
		self.dl_bytes = 0      # Total number of bytes downloaded (bodies only)
		self.dl_rate  = None   # Download rate (exponential moving average)
		self.dl_start = 0.0    # Time when the current download started
		self.prog     = 0.0    # Backup progress (percent)
		self.report   = 0      # Last reported progress

	def show(self):
		runtime  = self.op.duration
		progress = (self.update(), self.total, self.prog, runtime)
		dl_bytes = bytes_fmt(self.dl_bytes)
		ema_rate = bytes_fmt(0.0 if self.dl_rate is None else self.dl_rate)
		avg_rate = bytes_fmt(self.dl_bytes / runtime)
		report   = log.info

		report('--- Backup Status ---')
		report('     Mailbox: {!a}', self.imap.mbox['name'])
		report('    Progress: {} / {} ({:.3f}%) in {} sec', *progress)
		report('     Skipped: {}', self.skipped)
		report('      Queued: {}', len(self.dl_queue))
		report('  Downloaded: {} ({})', self.dl_count, dl_bytes)
		report('Current rate: {}/s', ema_rate)
		report('Overall rate: {}/s', avg_rate)
		report('--- End of Status ---')

	def update(self, n=None):
		if n:
			self.scanned += 1
			self.skipped += n - self.next_n
			self.next_n   = n + 1
		else:
			n = self.scanned + self.skipped

		done = (n - len(self.dl_queue))
		self.prog = done / self.total * 100.0

		prog = int(self.prog)
		if self.report != prog:
			log.info('Progress: {} / {} ({}%)', done, self.total, prog)
			self.report = prog
		return done

	def dl_begin(self):
		self.dl_start = walltime()

	def dl_done(self, count, bytes):
		now = walltime()
		self.dl_count += count
		self.dl_bytes += bytes
		self.dl_rate   = ema(self.dl_rate, bytes / (now - self.dl_start))
		self.update()

	def dl_failed(self, count):
		self.scanned -= count
		self.skipped += count
		log.warn('Failed to download {} message(s)', count)

	def done(self):
		if self.next_n != self.total + 1:
			self.update(self.total)
		self.show()
