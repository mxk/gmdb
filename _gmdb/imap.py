
#
# Written by Maxim Khitrov (July 2011)
#

from . import conf
from .imaplib2 import *
from .oauth import OAuth
from .util import *

import logging
import ssl
import _gmdb

log = logging.getLogger('gmdb.imap')

# Redirect imaplib2 output to the logging interface
debug_func(log.debug)

# Client ID information
_client_id = OrderedDict((
	('name',    'gmdb'),
	('version', _gmdb.__version__),
	('contact', _gmdb.__email__)
))

# Message attributes requested during a mailbox scan
_scan_map = {
	'UID':         'uid',
	'X-GM-MSGID':  'msg_id',
	'X-GM-LABELS': 'labels',
	'FLAGS':       'flags',
	'RFC822.SIZE': 'size'
}

# Message attributes requested during a body fetch
# Note: I don't know whether X-GM-THRID is immutable (it probably isn't), but
#       getting it during a scan doubles the scan time. As a result, it is
#       obtained only once with the body.
_body_map = {
	'UID':          'uid',
	'X-GM-THRID':   'thr_id',
	'INTERNALDATE': 'idate',
	'BODY.PEEK[]':  'body'
}

class IMAP4Control:
	"""IMAP controller that provides message download/upload logic."""

	def __init__(self, init=True):
		self.cn       = None  # IMAP4 instance
		self.srv_type = None  # Server type ('gmail' or 'imap')
		self.srv_id   = {}    # Server ID information
		self.mbox     = {}    # Mailbox status
		self.init     = init  # Automatic init flag

		# SSL or TLS context
		if conf.no_verify or not conf.CA_FILE:
			self.ssl_ctx = ssl_context()
		else:
			self.ssl_ctx = ssl_context(ssl.CERT_REQUIRED, conf.CA_FILE)

	def __enter__(self):
		"""Connect to the server."""
		srv = conf.server
		ssl = self.ssl_ctx if conf.ssl or srv.endswith(':993') else None
		cn  = IMAP4(srv, conf.timeout, ssl)
		try:
			self.cn = self._init(cn) if self.init else cn
			return self
		except Exception:
			cn.logout()
			raise

	def __exit__(self, exc_type=None, exc_val=None, exc_tb=None):
		"""Close server connection."""
		try:
			# Perform a graceful logout only if there are no active commands
			if self.cn.cmds:
				self.cn.poll()
			self.cn.logout(not self.cn.cmds)
		except Exception:
			log.exception('Logout command failed')
		finally:
			self.cn = None

	def find_mbox(self, name):
		"""Find one of the special Gmail mailboxes using XLIST flags.

		Valid names are: inbox, allmail, drafts, sent, spam, starred, and trash
		"""
		if name.lower() == 'inbox':
			return 'INBOX'
		if self.srv_type != 'gmail':
			return name
		flag = '\\' + name
		for _, flags, sep, full_name in self.cn.xlist(conf.GMAIL_REF, '%'):
			if flag in map(str.lower, flags):
				full_name = iutf7_decode(full_name)
				log.debug('Mailbox translation: {!a} -> {!a}', name, full_name)
				return full_name
		raise RuntimeError('mailbox translation failed for {!a}'.format(name))

	def select(self, mbox='INBOX', readonly=True):
		"""Select one of the mailboxes."""
		self._reset_mbox(mbox)
		try:
			self.cn.select(mbox, readonly).defer()
		except NO as exc:
			if not readonly and self.srv_type != 'gmail':
				log.warn('Mailbox {!a} does not exist, creating...', mbox)
				self.cn.create(mbox).defer()
				self.cn.select(mbox).defer()
			else:
				raise
		self.cn.check().defer()
		self._update_mbox()
		return self.mbox['exists']

	def noop(self):
		"""Request status updates from the server."""
		self.cn.noop()
		if self.cn.state == 'selected':
			self._update_mbox()
			return self.mbox['exists']
		return 0

	def scan(self, gm_raw=None, labels=True, break_notify=False):
		"""Read essential information about each message in the current mailbox.

		The gm_raw parameter is a string utilizing Gmail search syntax. Fetching
		of message labels may be disabled by setting labels to False, which
		increases scan rate at the cost of not knowing where each message is
		stored. Setting break_notify to True causes the generator to yield
		(None, None) between interval fetches.

		The generator yields an approximate progress indication (number of
		messages scanned) and a dictionary containing the attributes of the
		current message. The progress indication may be discontinuous when
		the search filter is used or if messages are deleted from the server
		during a scan (e.g. 1, 2, 3, 4, 1001, 1002, ...).
		"""
		# Create UID checkpoints
		uids, interval = self._checkpoints(conf.BATCH_SIZE)
		if not uids:
			return

		# Prepare filter criteria
		if gm_raw:
			log.info('Filter criteria: {!a}', gm_raw)
			gm_raw = qstr_or_lit(gm_raw)

		# Decide what attributes to request
		if labels:
			scan_map = _scan_map
		else:
			scan_map = _scan_map.copy()
			del scan_map['X-GM-LABELS']

		prog  = 0           # Progress (message count)
		uids  = iter(uids)  # UID checkpoints
		start = next(uids)  # First UID to fetch

		# Scan each interval from start to UIDNEXT
		for stop in uids:
			useq  = self._filter('{}:{}'.format(start, stop - 1), gm_raw)
			start = stop
			if useq:
				for n, msg in enumerate(self._fetch(useq, scan_map), prog + 1):
					if labels:
						msg['labels'] = list(map(iutf7_decode, msg['labels']))
					else:
						msg['labels'] = []
					yield (n, msg)
				self.noop()
			prog += interval
			if break_notify:
				yield (None, None)

	def fetch_body(self, msgs):
		"""Fetch the body and immutable attributes of one or more messages.

		The msgs parameter must be a dictionary of uid,msg pairs, where msg is
		a dictionary returned by scan() and uid is msg['uid'].
		"""
		# Can't run this in parallel with the scan
		self.cn.wait_all()
		for new_attrs in self._fetch(IMAP4SeqSet(msgs), _body_map):
			msg = msgs[new_attrs['uid']]
			msg.update(new_attrs)
			msg['idate'] = idate2unix(msg['idate'])
			yield msg

	def store(self, mbox, msg, body):
		"""Upload a single message to the current mailbox."""
		cmd = self.cn.append(mbox, body, msg['flags'], msg['idate'])
		cmd.defer()
		self._update_mbox()
		if self.srv_type != 'gmail':
			return

		# Get message UID (Gmail servers support UIDPLUS)
		if cmd.result.dtype == 'APPENDUID':
			uid = cmd.result[-1]
		else:
			raise IMAP4Error('failed to determine uid of uploaded message')

		# Set message labels
		labels = map(qstr_iutf7, msg['labels'])
		self.cn.store(uid, 'X-GM-LABELS.SILENT', *labels, uid=True)

	def _init(self, cn):
		"""Initialize new IMAP connection."""
		# Enable TLS encryption if SSL wasn't used
		if 'STARTTLS' in cn.caps:
			cn.starttls(self.ssl_ctx)

		# Authenticate via LOGIN or OAuth
		if conf.passwd:
			log.debug('Attempting LOGIN authentication...')
			cn.login(conf.account, conf.passwd)
		else:
			log.debug('Attempting OAuth authentication...')
			auth = OAuth(conf.OAUTH_KEY, conf.OAUTH_SECRET, conf.OAUTH_URL)
			cn.authenticate('XOAUTH', auth(conf.account))

		# Enable compression if requested
		if conf.compress:
			if 'COMPRESS=DEFLATE' in cn.caps:
				cn.compress(level=conf.compress * 3)
			else:
				log.warn('Server does not support data compression')

		# Identify server type and send client ID (only to Gmail servers)
		if 'X-GM-EXT-1' in cn.caps:
			self.srv_type = 'gmail'
			if 'ID' in cn.caps:
				for resp in cn.id(None if conf.PROTECT_ID else _client_id):
					self.srv_id = dict(group(resp[-1]))
					log.debug('Server ID: {}', self.srv_id)
		else:
			self.srv_type = 'imap'

		# Check account quota
		if 'QUOTA' in cn.caps:
			for resp in cn.getquota(''):
				for name, usage, limit in group(resp[-1], 3):
					if name.upper() == 'STORAGE':
						usage *= 1024
						limit *= 1024
						break
				else:
					continue
				log.info('Account quota: {} / {} ({:.1%})', bytes_fmt(usage),
				         bytes_fmt(limit), usage / limit)
		return cn

	def _reset_mbox(self, name=''):
		"""Reset mailbox information."""
		self.mbox = {
			'name':           name,
			'flags':          (),
			'exists':         0,
			'recent':         0,
			'unseen':         0,
			'permanentflags': (),
			'uidnext':        0,
			'uidvalidity':    0
		}

	def _update_mbox(self):
		"""Process all responses in the common queue."""
		for resp in map(self.cn.claim, self.cn.queued):
			dtype = resp.dtype.lower() if resp.dtype else None
			if dtype == 'alert':
				log.critical(resp.info)
			elif dtype == 'expunge':
				log.debug2('Message expunged ({})', resp[0])
				self.mbox['exists'] -= 1
			elif dtype in self.mbox:
				v = resp[0] if dtype in ('exists', 'recent') else resp[1]
				log.debug2('Status update: {}={}', resp.dtype, v)
				self.mbox[dtype] = v
			else:
				log.debug('Ignored response: {}', resp)

	def _checkpoints(self, interval):
		"""Get a list of checkpoint UIDs for the current mailbox.

		The interval is the maximum number of messages between two consecutive
		UIDs. The interval may be automatically increased in order to keep the
		request size within FETCH_LIMIT bytes.
		"""
		if interval < 1:
			raise ValueError('invalid checkpoint interval')

		exists  = self.mbox['exists']
		uidnext = self.mbox['uidnext']
		if not exists:
			return ([], interval)
		log.debug2('Creating checkpoints for {} messages [interval={}]...',
		           exists, interval)

		# Increase the interval until seq string is below FETCH_LIMIT bytes
		while True:
			rng = range(1, exists + 1, interval)
			seq = ','.join(map(str, rng))
			lsr = len(seq) / conf.FETCH_LIMIT
			if lsr <= 1.0:
				break
			interval = max(int(interval * lsr + 0.5), interval + 1)
			log.debug2('Increasing checkpoint interval to {}', interval)

		# Request UIDs for the chosen sequence numbers
		cmd = self.cn.fetch(seq, 'UID', wait=False)
		cmd.seqset = set(rng)
		uids = [uidnext]
		for resp in cmd:
			uids.extend(v for k, v in group(resp[-1]) if k.upper() == 'UID')
		cmd.check()

		num = len(uids)
		uids.sort()
		log.debug2('{} checkpoints for UIDs {}:{}', num, uids[0], uidnext - 1)

		# Sanity check
		if num != len(rng) + 1 or uids[-1] != uidnext:
			raise RuntimeError('failed to create UID checkpoints')

		self.noop()
		return (uids, interval)

	def _filter(self, useq, gm_raw):
		"""Filter a UID sequence using X-GM-RAW search."""
		if not gm_raw:
			return IMAP4SeqSet(useq)  # No filter specified
		match = IMAP4SeqSet()
		for resp in self.cn.search('UID', useq, 'X-GM-RAW', gm_raw, uid=True):
			match.update(resp[1:])
		log.debug2('Filter found {} match(es) in UIDs {}', len(match), useq)
		return match

	def _fetch(self, useq, fetch_map):
		"""Fetch the attributes of one or more messages in a single request."""
		if not useq:
			return
		rmap = response_map(fetch_map)
		done = len(rmap)
		msgs = defaultdict(dict)
		cmd  = self.cn.fetch(useq, *fetch_map, wait=False, uid=True)
		for resp in cmd:
			kv  = dict((k.upper(), v) for k, v in group(resp[-1]))
			uid = kv['UID']
			msg = msgs[uid]
			msg.update((rmap[k], v) for k, v in kv.items() if k in rmap)
			if len(msg) == done:
				del msgs[uid]
				yield msg
		if msgs:
			log.debug('Leftover data after fetch: {}', msgs)
		cmd.check('OK', 'NO')
		if cmd.result.status == 'NO':
			log.warn(cmd.result.info)  # Some messages couldn't be fetched

class XYZZY(IMAP4Command):
	caps = ('XYZZY',)
