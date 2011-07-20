
#
# Written by Maxim Khitrov (July 2011)
#

from gzip import GzipFile

from . import conf
from .util import *

import functools
import hashlib
import logging
import os
import shutil
import sqlite3
import time
import traceback

log = logging.getLogger('gmdb.db')

# Signed <-> unsigned conversion for 64-bit INTEGER columns (msg_id and thr_id)
int64  = lambda v: v if v < 2**63 else v - 2**64
uint64 = lambda v: v if v >= 0 else v + 2**64

os_path = os.path

#
###  Controller  ###############################################################
#

class DBError(Exception):
	pass

class DBControl:
	"""SQLite database controller."""

	def __init__(self, root):
		if not os_path.isabs(root):
			root = os_path.join(conf.ROOT_DIR, root)
		self.root = os_path.realpath(root)
		self.lock = LockFile(self._path('~lock'))
		self._reset()

	def __enter__(self):
		"""Open the database with exclusive access."""
		if not os_path.isdir(self.root):
			log.info('Creating database directory')
			os.makedirs(self.root, conf.DIR_MODE)
		self.lock.create()
		try:
			self._open()
			return self
		except Exception:
			self.lock.remove()
			raise

	def __exit__(self, exc_type=None, exc_val=None, exc_tb=None):
		"""Close the database and release exclusive access."""
		try:
			if self.op and self.op.active:
				if exc_type:
					res = 'abort' if exc_type is KeyboardInterrupt else 'error'
					self.op.finish(res, traceback.format_exc())
				else:
					self.op.finish()
			self.save_conf(False)
		except Exception:
			log.exception('Operation not finished')
			# Do not re-raise
		finally:
			self._close()
			self.lock.remove()

	def __contains__(self, msg_id):
		"""Check if the given msg_id is present in the database."""
		return self.get_digest(msg_id) in self.files

	def begin_op(self, name, *args, **kwargs):
		"""Begin new operation."""
		if self.op and self.op.active:
			raise DBError('previous operation is not finished')
		if self.cn.in_transaction:
			raise DBError('previous transaction is not finished')
		self.op = Op(self, name, *args, **kwargs)
		return self.op

	def history(self, name=None):
		"""Get a complete history of all operations."""
		if name is None:
			sql = 'SELECT * FROM op ORDER BY op_id'
			cur = self.cn.execute(sql)
		else:
			sql = 'SELECT * FROM op WHERE name = ? ORDER BY op_id'
			cur = self.cn.execute(sql, (name,))
		return [dict(row) for row in cur]

	def get_attrs(self, msg_id, labels=None):
		"""Load message attributes for the given msg_id."""
		sql = 'SELECT * FROM msg_view WHERE msg_id = ?'
		for attrs in map(dict, self.cn.execute(sql, (int64(msg_id),))):
			if labels is None:
				attrs['labels'] = qstr_split(attrs['labels'] or '')
			else:
				attrs['labels'] = labels
			attrs['flags'] = (attrs['flags'] or '').split()
			for k in ('msg_id', 'thr_id'):
				attrs[k] = uint64(attrs[k])
			return attrs
		return None

	def get_digest(self, msg_id):
		"""Get file digest for the given msg_id."""
		sql = 'SELECT digest FROM msg, file USING (file_id) WHERE msg_id = ?'
		for digest, in self.cn.execute(sql, (int64(msg_id),)):
			return digest
		return None

	def get_body(self, msg_id):
		"""Load message body for the given msg_id."""
		return self.files.read(self.get_digest(msg_id))

	def get_labels(self, msg_id=None):
		"""Get labels of a specific message or all labels in the database."""
		if msg_id is not None:
			sql = 'SELECT labels FROM lbl, msg USING (lbl_id) WHERE msg_id = ?'
			cur = self.cn.execute(sql, (int64(msg_id),))
		else:
			cur = self.cn.execute('SELECT labels FROM lbl')
		lbls = set()
		for labels, in cur:
			lbls.update(qstr_split(labels))
		return lbls

	def save_conf(self, reload=True):
		"""Save current configuration to the database."""
		items = ((v, k) for k, v in self.conf.items())
		self.cn.execute('BEGIN')
		with self.cn:
			self.cn.executemany('UPDATE conf SET value=? WHERE key = ?', items)
		if reload:
			self._load_conf()

	def attach_index(self, use_current=True):
		"""Attach the index database to the current connection."""
		cn       = self.cn
		fts_ver  = self._fts_version()
		idx_path = self._path(conf.DB_IDX_NAME)
		attached = True
		indexed  = self.conf['indexed']

		log.debug('Attaching index database...')
		cn.execute('ATTACH ? AS idx', (idx_path,))
		try:
			# (Re)create the index database, if needed
			uv, = next(cn.execute('PRAGMA idx.user_version'))
			if uv != conf.DB_IDX_VER:
				attached = False
				cn.execute('DETACH idx')

				if use_current:
					log.error("Index must be rebuilt (see 'index' command)")
					return False

				os.unlink(idx_path)
				cn.execute('ATTACH ? AS idx', (idx_path,))
				attached = True
				indexed  = False

			self._run_script(cn, 'init.sql', db='idx', sync=conf.DB_SYNC)
			if uv != conf.DB_IDX_VER:
				self._run_script(cn, 'index.sql', uv=conf.DB_IDX_VER,
				                 fts_ver=fts_ver, tok=conf.DB_FTS_TOK)

			# Update message index
			if not indexed:
				if use_current:
					log.warn("Index is out of date (see 'index' command)")
					return True
				start = walltime()
				self._update_index()
				log.debug('Index update took {:.3f} sec', walltime() - start)
				self.conf['indexed'] = 1
				self.save_conf(False)
			return True
		except Exception:
			if attached:
				cn.execute('DETACH idx')
			raise

	def cleanup(self):
		"""Remove old and unreferenced entries from the database."""
		cn = self.cn
		cn.execute('BEGIN')
		with cn:
			# Delete old operations
			if self.conf['retention']:
				lim = (unixtime() - self.conf['retention'],)
				sql = ' FROM op WHERE start < ?'
				num = next(cn.execute('SELECT COUNT(op_id)' + sql, lim))[0]
				if num:
					date = time.strftime('%Y-%m-%d', time.localtime(lim[0]))
					log.info('Removing {} operation(s) before {}', num, date)
					cn.execute('DELETE' + sql, lim)

			# Delete unreferenced files from disk and database
			sql = '''
				SELECT file_id, digest FROM file LEFT JOIN msg USING (file_id)
				WHERE msg.file_id IS NULL
			'''
			rm = self.files.remove
			for file_id, digest in cn.execute(sql):
				cn.execute('DELETE FROM file WHERE file_id = ?', (file_id,))
				rm(digest)

			# Delete unreferenced flags and labels
			for table in ('flag', 'lbl'):
				cn.execute('''
					DELETE FROM {0} WHERE {0}_id IN (
						SELECT {0}_id FROM {0}
						LEFT JOIN msg USING ({0}_id)
						WHERE msg.{0}_id IS NULL
					);
				'''.format(table))

		cn.executescript('VACUUM; ANALYZE;')

	def _path(self, *args):
		"""Create a full path relative to the database root."""
		return os_path.join(self.root, *args)

	def _open(self):
		"""Open SQLite database."""
		db_path = self._path(conf.DB_NAME)
		is_new  = not (os_path.isfile(db_path) and os_path.getsize(db_path))

		if getattr(conf, 'db_backup', False) and not is_new:
			log.info('Creating database backup: {}.bak', db_path)
			shutil.copy2(db_path, db_path + '.bak')

		log.debug('Opening database: {}', db_path)
		self.cn = sqlite3.connect(db_path, 1.0, sqlite3.PARSE_DECLTYPES, None)
		try:
			os.chmod(db_path, conf.FILE_MODE)
			self._init(self.cn, is_new)
			self._load_conf()
		except Exception:
			self._close()
			raise

	def _close(self):
		"""Close SQLite database."""
		if self.cn:
			try:
				log.debug('Closing database')
				self.cn.close()
				for name in (conf.DB_NAME, conf.DB_IDX_NAME):
					journal = self._path(name + '-journal')
					if os_path.isfile(journal) and not os_path.getsize(journal):
						log.debug('Removing {} journal', name)
						os.unlink(journal)
			except Exception:
				log.exception('Failed to close database')
				# Do not re-raise
			finally:
				self._reset()

	def _reset(self):
		"""Reset internal attributes."""
		self.cn    = None
		self.conf  = None
		self.files = None
		self.op    = None

	def _init(self, cn, is_new):
		"""Initialize database connection prior to use."""
		cn.row_factory = sqlite3.Row
		self._run_script(cn, 'init.sql', db='main', sync=conf.DB_SYNC)

		if is_new:
			log.debug('Creating database structure [ver={}]', conf.DB_VER)
			self._run_script(cn, 'create.sql', uv=conf.DB_VER)

		# Check database status
		uv, = next(cn.execute('PRAGMA user_version'))
		fk, = next(cn.execute('PRAGMA foreign_keys'), [None])

		if uv != conf.DB_VER:
			raise DBError('unexpected database version')
		if fk != 1:
			raise DBError('foreign key support is disabled')

		for row in cn.execute('SELECT op_id FROM op WHERE result IS NULL'):
			log.warn('Database contains an unfinished operation')
			break

	def _run_script(self, cn, name, **kwargs):
		"""Execute a SQL script from the 'misc' directory."""
		with open(os_path.join(conf.PKG_DIR, 'misc', name)) as fd:
			script = fd.read()
		if kwargs:
			script = script.format(**kwargs)
		try:
			cn.executescript(script)
		except Exception:
			try:
				# cn.in_transaction is always False here for some reason
				cn.execute('ROLLBACK')
			except sqlite3.OperationalError:
				pass
			raise

	def _load_conf(self):
		"""Load 'conf' table into memory and create file db interface."""
		db_conf = dict(self.cn.execute('SELECT key, value FROM conf'))
		for k, v in db_conf.items():
			if v and v.isdigit():
				db_conf[k] = int(v)
		self.conf  = db_conf
		self.files = FileDB(self.root, db_conf)

	def _fts_version(self):
		"""Determine which full-text search module is supported."""
		cn = self.cn
		if conf.DB_FTS_EXT:
			cn.enable_load_extension(True)
			cn.load_extension(conf.DB_FTS_EXT)
		cn.execute('ATTACH ":memory:" AS fts')
		try:
			for ver in conf.DB_FTS_VER:
				try:
					cn.execute('CREATE VIRTUAL TABLE fts.temp USING ' + ver)
					return ver
				except sqlite3.OperationalError:
					pass
			raise DBError('FTS module is not available')
		finally:
			cn.execute('DETACH fts')

	def _update_index(self):
		"""Populate or update message index."""
		cn = self.cn

		# Delete messages no longer present in 'file'
		cn.execute('BEGIN')
		with cn:
			cn.executescript('''
				DELETE FROM map WHERE digest NOT IN (SELECT digest FROM file);
				DELETE FROM fts WHERE docid  NOT IN (SELECT docid  FROM map);
			''')

		# Count the total number of new messages that need to be indexed
		sql = '''
			SELECT {} FROM file LEFT JOIN map USING (digest)
			WHERE map.digest IS NULL
		'''
		total, = next(cn.execute(sql.format('COUNT(digest)')))
		if not total:
			return

		# Index new messages
		from . import email
		log.info('Indexing {} new message(s)', total)

		sql_ins_map = 'INSERT INTO map (digest, date) VALUES (:digest, :date)'
		sql_ins_fts = '''
			INSERT INTO fts (docid, "from", "to", subject, body)
			VALUES (:docid, :from, :to, :subject, :body)
		'''
		cn.execute('BEGIN')
		err = log.exception if conf.verbose >= 2 else log.warn
		with cn:
			for n, (digest,) in enumerate(cn.execute(sql.format('digest')), 1):
				if n % 1000 == 0:
					log.debug('{} / {} ({:.3f})', n, total, n / total * 100.0)
				fd = self.files.open(digest)
				if fd is None:
					log.warn('Failed to open message file [digest={}]', digest)
					continue
				try:
					with fd:
						msg = email.parse(fd)
				except Exception:
					err('Failed to parse message [digest={}]', digest)
					continue
				msg['digest'] = digest
				msg['docid']  = cn.execute(sql_ins_map, msg).lastrowid
				cn.execute(sql_ins_fts, msg)
			log.debug('{0} / {0} (100.000%)', total)

#
###  Operations  ###############################################################
#

class Op(metaclass=RegisteredType):
	"""Operation base class."""

	def __new__(cls, db, name, *args, **kwargs):
		if cls is Op:
			cls = Op.registry[name]
			if cls.__new__ is not Op.__new__:
				return cls.__new__(cls, db, name, *args, **kwargs)
		return object.__new__(cls)

	def __init__(self, db, name, *, temp=False):
		start = unixtime()
		if temp:
			op_id = 0
		else:
			sql   = 'INSERT INTO op (name, start) VALUES (?,?)'
			op_id = db.cn.execute(sql, (name, start)).lastrowid

		self.db     = db     # DBControl instance
		self.name   = name   # Operation name ('backup', 'restore', etc.)
		self.id     = op_id  # Operation ID
		self.start  = start  # Start time
		self.stop   = None   # Stop time
		self.result = None   # Final result ('ok', 'abort', 'error')
		self.info   = None   # Additional result information

		if not temp:
			self.begin()
		log.info('Operation {} started ({})', op_id, name)

	def __enter__(self):
		return self

	def __exit__(self, exc_type=None, exc_val=None, exc_tb=None):
		self.rollback() if exc_type else self.commit()

	def begin(self):
		self.db.cn.in_transaction or self.db.cn.execute('BEGIN')

	def commit(self):
		self.db.cn.in_transaction and self.db.cn.commit()

	def rollback(self):
		self.db.cn.in_transaction and self.db.cn.rollback()

	def finish(self, result='ok', info=None):
		if not self.active:
			return
		if result not in ('ok', 'abort', 'error'):
			raise ValueError('invalid operation result {!a}'.format(result))
		self.commit() if result == 'ok' else self.rollback()

		# Break reference cycle when db is no longer needed
		cn = self.db.cn
		self.db = None

		self.stop   = unixtime()
		self.result = result
		self.info   = str(info) if info else None

		if self.id:
			sql = 'UPDATE op SET stop=?, result=?, info=? WHERE op_id = ?'
			cn.execute(sql, (self.stop, self.result, self.info, self.id))
		log.info('Operation {} finished in {} sec ({})', self.id,
		         self.duration, self.result)

	@property
	def active(self):
		"""Operation status."""
		return self.db is not None

	@property
	def duration(self):
		"""Operation run time in seconds."""
		return (unixtime() if self.stop is None else self.stop) - self.start

# Backup SQL statements
_update_sql = 'UPDATE msg SET op_id=?, flag_id=?, lbl_id=? WHERE msg_id = ?'
_insert_sql = '''
	REPLACE INTO msg (msg_id, op_id, file_id, flag_id, lbl_id, thr_id, idate)
	VALUES (?,?,?,?,?,?,?)
'''

class backup(Op):
	"""Backup operation."""

	def __init__(self, db, name):
		# Prevent backups of multiple accounts into the same database
		if conf.account != db.conf['account']:
			if db.conf['account'] is not None:
				raise DBError('account name mismatch')
			db.conf['account'] = conf.account

		# Index needs to be updated
		db.conf['indexed'] = 0
		db.save_conf(False)

		# Delayed 'msg' table insert/update queues (conf.DB_DELAYED_OPS)
		self.msg_insert = deque()
		self.msg_update = deque()

		super().__init__(db, name)
		if conf.filter:
			sql = 'UPDATE op SET filter=? WHERE op_id = ?'
			db.cn.execute(sql, (conf.filter, self.id))

	def commit(self):
		"""Execute delayed operations and commit the current transaction."""
		if not self.db.cn.in_transaction:
			return
		if self.msg_update:
			self.db.cn.executemany(_update_sql, self.msg_update)
			self.msg_update.clear()
		if self.msg_insert:
			self.db.cn.executemany(_insert_sql, self.msg_insert)
			self.msg_insert.clear()
		self.db.cn.commit()

	def rollback(self):
		"""Cancel current transaction."""
		if self.db.cn.in_transaction:
			self.msg_insert.clear()
			self.msg_update.clear()
			self.db.cn.rollback()

	def store(self, msg):
		"""Add a new message to the database."""
		msg_id  = int64(msg['msg_id'])
		thr_id  = int64(msg['thr_id'])
		idate   = msg['idate']
		file_id = self._store_file(msg['body'])
		flag_id = self._store_flags(msg['flags'])
		lbl_id  = self._store_labels(msg['labels'])
		entry   = (msg_id, self.id, file_id, flag_id, lbl_id, thr_id, idate)

		if conf.DB_DELAYED_OPS:
			self.msg_insert.append(entry)
		else:
			self.db.cn.execute(_insert_sql, entry)

	def update(self, msg):
		"""Update the mutable attributes of an existing message."""
		msg_id  = int64(msg['msg_id'])
		flag_id = self._store_flags(msg['flags'])
		lbl_id  = self._store_labels(msg['labels'])
		entry   = (self.id, flag_id, lbl_id, msg_id)

		if conf.DB_DELAYED_OPS:
			self.msg_update.append(entry)
		else:
			self.db.cn.execute(_update_sql, entry)

	def finish(self, result='ok', info=None):
		db = self.db
		super().finish(result, info)
		log.debug('Flag cache:  {}', self._flag_id.cache_info())
		log.debug('Label cache: {}', self._lbl_id.cache_info())
		if result == 'ok':
			log.info('Performing database maintenance...')
			start = walltime()
			db.cleanup()
			log.info('Maintenance finished in {:.3f} sec', walltime() - start)

	def _store_file(self, data):
		"""Write message data to disk and add/update its database entry."""
		digest = self.db.files.write(data)

		# Use REPLACE to avoid multiple msg references to the same file entry
		sql = 'INSERT OR REPLACE INTO file (op_id, digest, size) VALUES (?,?,?)'
		return self.db.cn.execute(sql, (self.id, digest, len(data))).lastrowid

	def _store_flags(self, flags):
		"""Store the list of flags in the database and return its ID."""
		if flags:
			flags.sort()
			return self._flag_id(' '.join(flags))
		return None

	def _store_labels(self, labels):
		"""Store the list of labels in the database and return its ID."""
		if labels:
			labels.sort()
			quote = lambda lbl: qstr(lbl, False)
			return self._lbl_id(' '.join(map(quote, labels)))
		return None

	@functools.lru_cache(None)
	def _flag_id(self, flags):
		"""Flag list cache."""
		sql = 'SELECT flag_id FROM flag WHERE flags = ?'
		for flag_id, in self.db.cn.execute(sql, (flags,)):
			return flag_id
		sql = 'INSERT INTO flag (flags) VALUES (?)'
		return self.db.cn.execute(sql, (flags,)).lastrowid

	@functools.lru_cache(500)
	def _lbl_id(self, labels):
		"""Label list cache."""
		sql = 'SELECT lbl_id FROM lbl WHERE labels = ?'
		for lbl_id, in self.db.cn.execute(sql, (labels,)):
			return lbl_id
		sql = 'INSERT INTO lbl (labels) VALUES (?)'
		return self.db.cn.execute(sql, (labels,)).lastrowid

class restore(Op):
	"""Restore operation."""

	def __init__(self, db, name, ids=None, pri=None, **kwargs):
		op_id, start = self._find_start(db)

		pri  = dict((lbl.lower(), n) for n, lbl in enumerate(pri or ()))
		last = len(pri)
		pkey = lambda lbl: pri.get(lbl, last)
		ymd  = time.strftime('GMDB-%Y%m%d', time.localtime(start))

		super().__init__(db, name, **kwargs)

		self.msg_ids  = ids    # Message IDs to restore (None = all)
		self.start_op = op_id  # First usable backup operation (0 = all)
		self.pri_key  = pkey   # Label priority sort key
		self.bkp_lbl  = ymd    # Default label added to all messages

	def count(self):
		"""Get the total number of messages to be restored."""
		if self.msg_ids:
			return len(self.msg_ids)
		sql = 'SELECT COUNT(msg_id) FROM msg WHERE op_id >= ?'
		for count, in self.db.cn.execute(sql, (self.start_op,)):
			return count

	def mbox_map(self, srv_type):
		"""Create a map of mailbox names to final message labels."""
		is_gmail = srv_type == 'gmail'  # Server type
		mbox_map = defaultdict(list)    # mbox->[(lbl_id, labels), ...]

		sql = 'SELECT lbl_id, labels FROM lbl UNION ALL SELECT NULL, ""'
		for lbl_id, labels in self.db.cn.execute(sql):
			mbox, labels = self._mbox_labels(qstr_split(labels), is_gmail)
			mbox_map[mbox].append((lbl_id, labels))
		return mbox_map

	def attrs(self, mbox_map):
		"""Generator of message attributes.

		The generator yields (mbox, msg) tuples, where mbox is the destination
		mailbox and msg is a dictionary of message attributes as returned by
		DBControl.get_attrs, but with an updated list of lables. The tuples are
		grouped by mailbox name. When restoring to Gmail, mbox will be one of
		'allmail', 'spam', or 'trash'. Otherwise, mbox is the name of an actual
		mailbox, which may need to be created.
		"""
		db  = self.db
		ids = self.msg_ids

		sql_id   = 'SELECT msg_id FROM msg WHERE op_id >= ? AND lbl_id = ?'
		sql_null = 'SELECT msg_id FROM msg WHERE op_id >= ? AND lbl_id IS NULL'

		for mbox, entries in mbox_map.items():
			for lbl_id, labels in entries:
				if lbl_id is None:
					sql, args = sql_null, (self.start_op,)
				else:
					sql, args = sql_id, (self.start_op, lbl_id)
				for msg_id, in db.cn.execute(sql, args):
					if not ids or msg_id in ids:
						yield (mbox, db.get_attrs(msg_id, labels))

	def body(self, msg):
		"""Load message body."""
		return self.db.get_body(msg['msg_id'])

	def _find_start(self, db):
		"""Find the ID and timestamp of the first usable backup operation."""
		sql = 'SELECT MAX(op_id) FROM op WHERE name="backup" AND result="ok"'
		for op_id, in db.cn.execute(sql):
			if op_id is not None:
				break
		else:
			# No successful backups, start with the first failed one
			sql = 'SELECT MIN(op_id) FROM op WHERE name="backup"'
			for op_id, in db.cn.execute(sql):
				if op_id is not None:
					log.warn('Database does not contain any successful backups')
					break
			else:
				raise DBError('database does not contain any backups')

		# Get the start time of the first usable backup
		sql = 'SELECT start FROM op WHERE op_id = ?'
		for start, in db.cn.execute(sql, (op_id,)):
			return (0 if conf.all or conf.ids else op_id, start)

	def _mbox_labels(self, orig, is_gmail):
		"""Get destination mailbox and final labels for restoration."""
		mbox = 'allmail'
		base = conf.set_label or orig
		lbls = OrderedDict((lbl.lower(), lbl) for lbl in base if lbl)

		# Merge additional labels
		if conf.add_label:
			lbls.update((lbl.lower(), lbl) for lbl in conf.add_label if lbl)

		# Extract ^Spam and ^Trash labels, and update destination mailbox
		for k in ('^spam', '^trash'):
			if k in lbls:
				del lbls[k]
				mbox = k[1:]

		# Convert lbls dict to a tuple
		if is_gmail:
			lbls = tuple(lbls.values()) + (self.bkp_lbl,)
		elif lbls:
			# Strip leading backslash from special Gmail labels
			for k in map(str.lower, conf.GMAIL_SPECIAL):
				if k in lbls:
					lbls[k[1:]] = lbls.pop(k)[1:]

			# Add the default 'All Mail' label
			lbls['all mail'] = 'All Mail'

			# Sort labels by their priority
			lbls = tuple(lbls[l] for l in sorted(lbls, key=self.pri_key))
		else:
			lbls = ('All Mail',)

		# Prepend prefix
		if conf.prefix:
			prefix = conf.prefix
			lbls = tuple(prefix + lbl for lbl in lbls)

		# Determine the final location
		if is_gmail:
			return (mbox, lbls)
		if mbox == 'allmail':
			return (lbls[0], lbls)
		prefix = conf.prefix or ''
		return (prefix + mbox.capitalize(), lbls)

#
###  File database  ############################################################
#

class FileDB(metaclass=RegisteredType):
	"""Class for storing and loading messages using their digests."""

	_registry_key = 'comp_method'

	def __new__(cls, root, db_conf):
		if cls is FileDB:
			cls = FileDB.registry.get(db_conf['comp_method'], 'none')
			if cls.__new__ is not FileDB.__new__:
				return cls.__new__(cls, root, db_conf)
		return object.__new__(cls)

	def __init__(self, root, db_conf):
		self.root = os_path.realpath(root)
		self.tmp  = os_path.join(self.root, 'tmp')
		self.hash = getattr(hashlib, db_conf.get('digest', 'sha1'))

		self.dir_levels = max(1, min(db_conf.get('dir_levels', 1), 8))
		self.comp_level = db_conf.get('comp_level', 6)

		# Create a directory for temporary files (root must already exist)
		if not os_path.isdir(self.tmp):
			os.mkdir(self.tmp, conf.DIR_MODE)

	def __contains__(self, digest):
		"""Check if the given digest exists."""
		return digest and os_path.isfile(self._path(digest))

	def __iter__(self):
		"""Iterate over all available digests."""
		ls   = os.listdir
		join = os_path.join
		b16  = frozenset('0123456789abcdef')
		tree = deque(((0, ''),))
		while tree:
			n, d = tree.pop()
			path = join(self.root, d)
			if n < self.dir_levels:
				n += 1
				tree.extend((n, join(d, s)) for s in ls(path) if s in b16)
			else:
				for digest in ls(path):
					yield digest

	def digest(self, data):
		"""Calculate message digest."""
		return self.hash(data).hexdigest()

	def open(self, digest):
		"""Open a message file for reading."""
		if digest:
			path = self._path(digest)
			if os_path.isfile(path):
				return self._open(path, 'rb')
		return None

	def read(self, digest):
		"""Read message contents from disk."""
		fd = self.open(digest)
		if fd is not None:
			with fd:
				return fd.read()

	def write(self, data, digest=None, overwrite=False):
		"""Write message contents to disk."""
		if not digest:
			digest = self.digest(data)

		path   = self._path(digest)
		exists = os_path.isfile(path)
		tmp    = os_path.join(self.tmp, digest)

		if exists and not overwrite:
			log.warn('Duplicate digest: {}', digest)
			return digest
		try:
			with self._open(tmp, 'wb') as fd:
				os.chmod(tmp, conf.FILE_MODE)
				fd.write(data)
			if not exists:
				parent = os_path.dirname(path)
				if not os_path.isdir(parent):
					os.makedirs(parent, conf.DIR_MODE)
			elif os.name == 'nt':
				os.unlink(path)  # os.rename doesn't overwrite on Windows
			os.rename(tmp, path)
			return digest
		except Exception:
			if os_path.isfile(tmp):
				os.unlink(tmp)
			raise

	def remove(self, digest):
		"""Remove message contents from disk."""
		if digest:
			path = self._path(digest)
			if os_path.isfile(path):
				os.unlink(path)
			try:
				os.removedirs(os_path.dirname(path))
			except OSError:
				pass

	@property
	def empty(self):
		"""Database is empty flag."""
		for digest in self:
			return False
		return True

	def _path(self, digest):
		"""Get full path to the given digest."""
		steps = list(digest[:self.dir_levels])
		steps.append(digest)
		return os_path.join(self.root, *steps)

	def _open(self, path, mode='rb'):
		"""Open a file for reading or writing."""
		return open(path, mode)

class FileDB_None(FileDB):
	comp_method = 'none'

class FileDB_Gzip(FileDB):
	comp_method = 'gzip'

	def _open(self, path, mode='rb'):
		fd = GzipFile(path, mode, self.comp_level)
		fd.read1 = fd.read  # Bug fix for email parser
		return fd
