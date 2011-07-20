
#
# Written by Maxim Khitrov (July 2011)
#

from . import Command, SigHandler, load_ids
from .. import IMAP4Control, DBControl, conf
from ..util import *

import argparse
import logging
import socket

def load_pri(fd):
	if fd is None:
		return None
	try:
		return [line for line in map(str.strip, fd) if line]
	finally:
		if not is_stdin(fd):
			fd.close()

def check_abort():
	if sig.abort:
		raise KeyboardInterrupt

class restore(Command):
	"""Restore messages from the database.

	By default, the command restores all messages from the most recent
	successful backup (and all subsequent failed/aborted backups, if any). This
	restores your mailbox to its last complete state. Messages that were deleted
	prior to the most recent successful backup are not restored.

	You may restore all messages in the database by specifying --all (-A) on the
	command line. Alternatively, you may select specific messages for
	restoration by creating a text file that lists one message ID per line, and
	passing the file name to the --ids (-I) parameter. This file is typically
	created by using the 'search' command. Note that while you may pipe output
	of another command to stdin by specifying '--ids -' on the command-line,
	piping the output of 'search' will not work, because both commands require
	exclusive database access.

	Messages may be restored back to Gmail or any other IMAP4rev1 server (N.B.
	the term 'IMAP4' is used hereafter to refer to all non-Gmail IMAP4 servers).
	Restoration to Gmail is lossless (i.e. all message labels and other
	attributes are preserved). Restoration to an IMAP4 server causes all but one
	of the labels to be lost; messages are uploaded to a single mailbox and are
	not copied anywhere else. Which label to use for the final destination is
	determined by the --priority (-r) parameter, which specifies a file that
	lists one label per line in the order of their priority (see 'labels'
	command). The following algorithm is used to determine the final location of
	each message:

	  1. If --set-label is unspecified, load the original list of labels from
	     the database. Otherwise, use the label(s) specified with --set-label.
	  2. For each --add-label option, append label name to the list.
	  3. Remove '^Spam' and '^Trash' labels from the list (if present), but
	     remember their presence.

	  If restoring to Gmail:

	     a. Append "GMDB-YYYYMMDD" label to the list, where "YYYYMMDD" is the
	        date of the most recent successful backup (or the first unsuccessful
	        one).

	  Otherwise:

	     a. Strip the leading backslash from special labels (\Inbox, \Important,
	        \Draft, \Sent, \Starred, \Sent).
	     b. Add 'All Mail' to the list of labels.
	     c. If --priority file is specified (it should be), sort the list of
	        labels according to their order in the priority file (first line =
	        highest priority). Comparison is case-insensitive.

	  4. If --prefix is specified, prepend the prefix string to all labels in
	     the list.
	  5. If restoring to Gmail, upload the message to 'All Mail', 'Spam', or
	     'Trash' mailbox, depending on the action taken in step 3. Apply all
	     labels in the list to the uploaded message.
	  6. Otherwise, upload the message to the mailbox named after the first
	     label in the list, or 'Spam' or 'Trash' if either one was found in step
	     3.
	"""

	uses_imap = True
	uses_db   = True

	def __call__(self):
		global log, sig

		log = logging.getLogger('gmdb.cmd.restore')
		err = log.exception if conf.verbose else log.error
		ids = load_ids(conf.ids)
		pri = load_pri(conf.priority)

		if conf.db is None:
			conf.db = conf.account
		if conf.show_map:
			logging.getLogger().setLevel(logging.WARNING)
		try:
			with SigHandler() as sig, DBControl(conf.db) as db:
				log.info('Source account: {!a}', db.conf['account'])
				log.info('Target account: {!a}', conf.account)
				op = db.begin_op('restore', ids, pri, temp=conf.show_map)
				with IMAP4Control() as self.imap:
					self._restore(sig, op)
					op.finish()
					return 0
		except KeyboardInterrupt:
			err('Restore interrupted by user')
		except socket.timeout:
			err('Connection timeout')
		except Exception as exc:
			msg = str(exc)
			err(msg[:1].upper() + msg[1:])
		return 1

	@staticmethod
	def build_args(subp):
		rtype = subp.add_mutually_exclusive_group()
		rtype.add_argument('-A', '--all', action='store_true',
			help='restore all messages, including those that were deleted')
		rtype.add_argument('-I', '--ids', metavar='FILE',
			type=argparse.FileType(), help='file with message ids to restore')
		subp.add_argument('-l', '--set-label', metavar='LABEL', action='append',
			help='starting labels for each message (may be repeated)')
		subp.add_argument('-a', '--add-label', metavar='LABEL', action='append',
			help='additional labels for each message (may be repeated)')
		subp.add_argument('-r', '--priority', metavar='FILE',
			type=argparse.FileType(), help='label priority file')
		subp.add_argument('-f', '--prefix', metavar='LABEL',
			help='add a prefix to all message labels (e.g. "Restored/")')
		subp.add_argument('-e', '--resume', action='store_true',
			help='resume the previous restore operation if it did not finish')
		subp.add_argument('-m', '--show-map', action='store_true',
			help='show mailbox restore map and exit')
		subp.add_argument('-d', '--db', metavar='DIR',
			help='database directory (defaults to account name)')
		subp.add_argument('account',
			help='login account (e.g. someuser@example.com)')

	def _restore(self, sig, op):
		imap     = self.imap
		is_gmail = imap.srv_type == 'gmail'
		db_conf  = op.db.conf
		resume   = db_conf['resume'] if conf.resume else None
		mbox_map = op.mbox_map(imap.srv_type)

		if conf.show_map:
			shown = set()
			for mbox, entries in sorted(mbox_map.items()):
				for lbl_id, labels in entries:
					pair = (mbox, labels)
					if pair not in shown:
						print('* {} <- {}'.format(mbox, ' | '.join(labels)))
						shown.add(pair)
			return

		prev_mbox = None
		mbox_name = None

		status = Status(op, imap)
		sig.enable_status(status)

		for mbox, msg in op.attrs(mbox_map):
			check_abort()
			msg_id = msg['msg_id']

			# Resume previous operation
			if resume is not None:
				if msg_id == resume:
					log.info('Resuming previous restore operation...')
					resume = None
				status.skip()
				continue

			# Check if the mailbox has changed
			if mbox != prev_mbox:
				prev_mbox = mbox
				mbox_name = imap.find_mbox(mbox)
				imap.select(mbox_name, readonly=False)

			# Upload message to the server
			body = op.body(msg)
			if body is None:
				log.warn('Failed to load message body [msg_id={}]', msg_id)
				continue
			status.ul_begin()
			imap.store(mbox_name, msg, body)
			status.ul_done(1, len(body))
			db_conf['resume'] = msg_id

		db_conf['resume'] = None
		status.done()

class Status:
	def __init__(self, op, imap):
		total = op.count()
		log.info('Progress: 0 / {} (0%)', total)

		self.op       = op     # Current database operation
		self.imap     = imap   # IMAP4 connection
		self.total    = total  # Total number of messages in the mailbox
		self.skipped  = 0      # Number of messages skipped (when resuming)
		self.ul_count = 0      # Number of messages uploaded
		self.ul_bytes = 0      # Total number of bytes uploaded (bodies only)
		self.ul_rate  = None   # Upload rate (exponential moving average)
		self.ul_start = 0.0    # Time when the current upload started
		self.prog     = 0.0    # Restore progress (percent)
		self.report   = 0      # Last reported progress

	def show(self):
		runtime  = self.op.duration
		progress = (self.update(), self.total, self.prog, runtime)
		ul_bytes = bytes_fmt(self.ul_bytes)
		ema_rate = bytes_fmt(0.0 if self.ul_rate is None else self.ul_rate)
		avg_rate = bytes_fmt(self.ul_bytes / runtime)
		report   = log.info

		report('--- Restore Status ---')
		report('     Mailbox: {!a}', self.imap.mbox['name'])
		report('    Progress: {} / {} ({:.3f}%) in {} sec', *progress)
		report('     Skipped: {}', self.skipped)
		report('    Uploaded: {} ({})', self.ul_count, ul_bytes)
		report('Current rate: {}/s', ema_rate)
		report('Average rate: {}/s', avg_rate)
		report('--- End of Status ---')

	def update(self):
		done = self.skipped + self.ul_count
		self.prog = done / self.total * 100.0

		prog = int(self.prog)
		if self.report != prog:
			log.info('Progress: {} / {} ({}%)', done, self.total, prog)
			self.report = prog
		return done

	def skip(self):
		self.skipped += 1
		self.update()

	def ul_begin(self):
		self.ul_start = walltime()

	def ul_done(self, count, bytes):
		now = walltime()
		self.ul_count += count
		self.ul_bytes += bytes
		self.ul_rate   = ema(self.ul_rate, bytes / (now - self.ul_start))
		self.update()

	def done(self):
		self.skipped += self.total - self.ul_count
		self.show()
