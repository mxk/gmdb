
#
# Written by Maxim Khitrov (July 2011)
#

"""
IMAP4rev1 client implementation based on [RFC-3501].

Implemented RFCs:

* http://tools.ietf.org/html/rfc2087 - IMAP4 QUOTA extension
* http://tools.ietf.org/html/rfc2088 - IMAP4 non-synchronizing literals
* http://tools.ietf.org/html/rfc2152 - UTF-7
* http://tools.ietf.org/html/rfc2177 - IMAP4 IDLE command
* http://tools.ietf.org/html/rfc2193 - IMAP4 Mailbox Referrals
* http://tools.ietf.org/html/rfc2195 - IMAP/POP AUTHorize Extension
* http://tools.ietf.org/html/rfc2342 - IMAP4 Namespace
* http://tools.ietf.org/html/rfc2971 - IMAP4 ID extension
* http://tools.ietf.org/html/rfc3501 - IMAP VERSION 4rev1
* http://tools.ietf.org/html/rfc3502 - IMAP MULTIAPPEND
* http://tools.ietf.org/html/rfc3516 - IMAP4 Binary Content Extension
* http://tools.ietf.org/html/rfc3691 - UNSELECT command
* http://tools.ietf.org/html/rfc4314 - IMAP4 Access Control List (ACL) Extension
* http://tools.ietf.org/html/rfc4315 - UIDPLUS extension
* http://tools.ietf.org/html/rfc4959 - SASL Initial Client Response
* http://tools.ietf.org/html/rfc4978 - The IMAP COMPRESS Extension
* http://tools.ietf.org/html/rfc5161 - The IMAP ENABLE Extension
* http://tools.ietf.org/html/rfc5256 - SORT and THREAD Extensions
* http://tools.ietf.org/html/rfc5464 - The IMAP METADATA Extension

Informational RFCs:

* http://tools.ietf.org/html/rfc2062 - Obsolete Syntax
* http://tools.ietf.org/html/rfc2180 - IMAP4 Multi-Accessed Mailbox Practice
* http://tools.ietf.org/html/rfc2683 - Implementation Recommendations
* http://tools.ietf.org/html/rfc3348 - Child Mailbox Extension
* http://tools.ietf.org/html/rfc5032 - WITHIN Search Extension

TODO:

* http://tools.ietf.org/html/rfc1731 - IMAP4 Authentication Mechanisms
* http://tools.ietf.org/html/rfc4469 - IMAP CATENATE Extension
* http://tools.ietf.org/html/rfc5258 - IMAP4 LIST Command Extensions
* http://tools.ietf.org/html/rfc5267 - IMAP CONTEXT
* http://tools.ietf.org/html/rfc4731 - IMAP4 Extension to SEARCH
* http://tools.ietf.org/html/rfc5182 - Last SEARCH Result Reference

"""

__version__ = '1.0'
__author__  = 'Maxim Khitrov'
__email__   = 'max@mxcrypt.com'

__all__ = [
	'qstr', 'qstr_or_lit', 'qstr_iutf7', 'ssl_context', 'group', 'ungroup',
	'response_map', 'idate2unix', 'unix2idate', 'iutf7_decode', 'iutf7_encode',
	'debug_level', 'debug_func', 'IMAP4Error', 'ProtocolError', 'ParseError',
	'AccessModeError', 'UIDValidityError', 'StatusError', 'OK', 'NO', 'BAD',
	'BYE', 'IMAP4', 'IMAP4Command', 'IMAP4Response', 'IMAP4SeqSet', 'IMAP4Test'
]

from base64 import b64decode, b64encode
from collections import OrderedDict, deque
from select import select

import calendar
import errno
import hmac
import io
import itertools
import random
import re
import socket
import sys
import threading
import time
import zlib

try:
	import ssl
except ImportError:
	ssl = None

#
###  Utility functions  ########################################################
#

def qstr(s, validate=True):
	"""Return a quoted string after escaping '\' and '"' characters.

	When validate is set to True (default), the string must consist only of
	7-bit ASCII characters excluding NULL, CR, and LF.
	"""
	if validate:
		s.encode('ascii')
		if '\0' in s or '\r' in s or '\n' in s:
			raise ValueError('string contains NULL, CR, or LF characters')
	return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'

def qstr_or_lit(s, encoding='utf-8'):
	"""Return a quoted string or a literal bytes object.

	An existing bytes object is returned unmodified. A string is encoded using
	qstr() if it contains only 7-bit ASCII characters. Otherwise, the string is
	encoded into a bytes object using the given encoding (UTF-8 by default).
	"""
	if isinstance(s, _lit_types):
		return s
	try:
		return qstr(s)
	except ValueError:  # or UnicodeEncodeError
		return s.encode(encoding)

def qstr_iutf7(s):
	"""Return a quoted string, encoding any non-ASCII characters as UTF-7."""
	return qstr(iutf7_encode(s))

def ssl_context(verify_mode=None, cafile=None, capath=None, default=True):
	"""Create new SSL context."""
	if not ssl:
		raise RuntimeError('ssl support is disabled')
	ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
	ctx.set_ciphers('HIGH:!aNULL:@STRENGTH')
	if default:
		ctx.set_default_verify_paths()
	if verify_mode is None:
		_debug2('SSL certificate verification disabled')
		ctx.verify_mode = ssl.CERT_NONE
	else:
		if cafile:
			_debug2('SSL CA file: {}', cafile)
		if capath:
			_debug2('SSL CA path: {}', capath)
		if verify_mode == ssl.CERT_OPTIONAL:
			_debug2('SSL certificate hostname verification disabled')
		ctx.verify_mode = verify_mode
		if cafile or capath or not default:
			ctx.load_verify_locations(cafile, capath)
	return ctx

def group(seq, n=2):
	"""Convert a sequence into tuples, each containing n consecutive items."""
	i = (iter(seq),) * n
	return zip(*i)

def ungroup(items):
	"""Inverse of group."""
	for g in items:
		for v in g:
			yield v

def response_map(fetch_map):
	"""Create an expected FETCH response map from the given request map.

	Most of the keys returned in a FETCH response are unmodified from the
	request. The exceptions are BODY.PEEK and BODY partial range. A BODY.PEEK
	request is answered without the .PEEK suffix. A partial range (e.g.
	BODY[]<0.1000>) has the octet count (1000) removed, since that information
	is provided in the literal size (and may be different if the data was
	truncated).
	"""
	if not isinstance(fetch_map, dict):
		fetch_map = dict((v, v) for v in fetch_map)
	rmap = {}
	for k, v in fetch_map.items():
		for name in ('BODY', 'BINARY'):
			if k.startswith(name):
				k = k.replace(name + '.PEEK', name, 1)
				if k.endswith('>'):
					k = k.rsplit('.', 1)[0] + '>'
		rmap[k] = v
	return rmap

#
# INTERNALDATE codec
#

_months = { 1: 'Jan', 'Jan': 1,   2: 'Feb', 'Feb': 2,   3: 'Mar', 'Mar': 3,
            4: 'Apr', 'Apr': 4,   5: 'May', 'May': 5,   6: 'Jun', 'Jun': 6,
            7: 'Jul', 'Jul': 7,   8: 'Aug', 'Aug': 8,   9: 'Sep', 'Sep': 9,
           10: 'Oct', 'Oct': 10, 11: 'Nov', 'Nov': 11, 12: 'Dec', 'Dec': 12}

def idate2unix(idate):
	"""Convert INTERNALDATE to a Unix timestamp."""
	dmY, HMS, tz = idate.split()
	d, m, Y = dmY.split('-')
	H, M, S = HMS.split(':')

	# Build a struct_time tuple and convert '[+-]HHMM' to seconds
	st = (int(Y), _months[m], int(d), int(H), int(M), int(S), -1, -1, 0)
	tz = (-60 if tz[0] == '-' else 60) * (int(tz[1:3]) * 60 + int(tz[3:5]))
	return calendar.timegm(st) - tz

def unix2idate(ts):
	"""Convert a Unix timestamp to INTERNALDATE format (unquoted)."""
	st  = time.gmtime(ts)
	dmY = '{:02}-{}-{}'.format(st.tm_mday, _months[st.tm_mon], st.tm_year)
	HMS = '{:02}:{:02}:{:02}'.format(st.tm_hour, st.tm_min, st.tm_sec)
	return ' '.join((dmY, HMS, '+0000'))

#
# Mailbox name codec (modified UTF-7)
#

def iutf7_decode(s):
	"""IMAP UTF-7 decoder implemented according to [RFC-3501] section 5.1.3.

	The decoder does not verify that base64 sections are only used to represent
	characters outside of the ascii printable range.
	"""
	if isinstance(s, bytes):
		s = s.decode('ascii')
	start = s.find('&')
	if start == -1:
		# String consists only of printable US-ASCII characters, excluding '&'
		return s
	parts = []
	ascii = 0
	while start != -1:
		parts.append(s[ascii:start])
		stop  = s.find('-', start)
		ascii = stop + 1
		if stop == -1:
			raise UnicodeTranslateError(s, start, len(s),
			                            'utf-7 string ends in base64 mode')
		if stop == start + 1:
			# Found '&-' pair
			b64 = None
			parts.append('&')
		else:
			# Found base64 section (using inexact padding should be ok here)
			b64 = s[start + 1:stop].encode('ascii') + b'=='
			parts.append(b64decode(b64, b'+,').decode('utf-16-be'))
		start = s.find('&', ascii)
		if b64 and start == ascii and s[start:start + 2] != '&-':
			raise UnicodeTranslateError(s, start - 1, start + 1,
			                            'utf-7 string contains a null shift')
	parts.append(s[ascii:])
	return ''.join(parts)

def iutf7_encode(s):
	"""IMAP UTF-7 encoder."""
	parts = []
	start = None
	for i, c in enumerate(s):
		if 0x20 <= ord(c) <= 0x7E:
			if start is not None:
				# End of non-ASCII section
				parts.append(_iutf7_b64encode(s[start:i]))
				start = None
			# Printable US-ASCII
			parts.append('&-' if c == '&' else c)
		elif start is None:
			# Start of non-ASCII section
			start = i
	if start is not None:
		parts.append(_iutf7_b64encode(s[start:]))
	return ''.join(parts)

def _iutf7_b64encode(s):
	b64 = b64encode(s.encode('utf-16-be'), b'+,').decode('ascii')
	return '&' + b64.rstrip('=') + '-'

#
# Debugging
#

CHECK_CAPS  = True  # Change to False to skip server capability checks
CHECK_STATE = True  # Change to False to skip command state checks

def debug_level(level):
	"""Set library debug level.

	Level descriptions:
	  1 - Information about connection events
	  2 - Detailed internal state updates
	  3 - Command execution events
	  4 - Raw data stream (excluding literals)
	  5 - Response parser output for each server response (including literals)
	"""
	global _debug_level
	ns = globals()
	for i in range(1, 6):
		# A bit of a hack, but this eliminates extra function calls
		ns['_debug' + str(i)] = _debug if i <= level else _debugX
	_debug_level = level
	_debug1('Debug level: {}', level)

def debug_func(func):
	"""Set library debug function."""
	global _debug
	assert callable(func)
	old = _debug
	_debug = func
	debug_level(_debug_level)
	return old

def _debug(msg, *args):
	"""Default debug function."""
	line = ('[imaplib2]', msg.format(*args) if args else str(msg), '\n')
	sys.stderr.write(' '.join(line))

_debugX = lambda msg, *args: None
debug_level(0)

#
###  Exceptions  ###############################################################
#

class IMAP4Error(Exception):
	"""Base IMAP exception."""

	def __str__(self):
		if len(self.args) == 2:
			return '{} [{}]'.format(*self.args)  # Message [Reason]
		return Exception.__str__(self)

class ProtocolError(IMAP4Error):
	"""Error in IMAP data stream."""

class ParseError(IMAP4Error):
	"""Failed to parse a server response."""

class AccessModeError(IMAP4Error):
	"""Access mode of the selected mailbox changed unexpectedly."""

class UIDValidityError(ProtocolError):
	"""UIDVALIDITY of the selected mailbox has changed unexpectedly.

	This error should never happen, but it is here just in case. See [RFC-2683]
	section 3.4.3 (last paragraph on page 13) for additional information.
	"""

class StatusError(IMAP4Error):
	"""Parent class of OK, NO, BAD, and BYE exceptions."""

	def __init__(self, msg, reason=None, response=None, command=None):
		if reason is None:
			super().__init__(msg)
		else:
			super().__init__(msg, reason)
		self.response = response
		self.command  = command

class OK(StatusError):
	"""Command completed with an 'OK' response.

	This is not normally an error condition, but it will be raised if the caller
	did not expect an 'OK' response (e.g. using SELECT or EXAMINE command with a
	non-existent mailbox name in lieu of UNSELECT).
	"""

class NO(StatusError):
	"""Command completed with a 'NO' response."""

class BAD(StatusError, ProtocolError):
	"""Command completed with a 'BAD' response (may be untagged)."""

class BYE(StatusError):
	"""Server closed the connection outside of a LOGOUT command."""

#
###  IMAP4 connection  #########################################################
#

# All valid connection states, see diagram on page 15 of [RFC-3501]
_all_states = {'!auth', 'auth', 'selected', 'logout'}

# Literal data types
_lit_types = (bytes, bytearray, memoryview)

def _readline(file, tags=None):
	"""Read a complete protocol line (text + literals) from file.

	The file object must support a readline method, which returns a decoded
	string with the trailing '\r\n' sequence removed, and a read method, which
	returns a bytes object of the specified length.

	The return value is a tuple containing a complete line of text and an
	optional list of undecoded literals. All octet counts in the original line
	are replaced with indices into the list of literals. For example:

	('* OK Gimap ready for requests', None)
	('* 1 FETCH (BODY[HEADER] {0} BODY[] {1})', [b'header', b'body'])
	"""
	line = file.readline()
	if tags and not line.startswith(tags):
		raise ProtocolError('invalid response tag', line)
	if line[-1] != '}':
		return (line, None)  # No literals
	text = []
	data = []
	while True:
		line, nbytes = line.rsplit('{', 1)
		text.extend((line, '{', str(len(data)), '}'))   # Index into data
		data.append(file.read(int(nbytes[:-1])))        # Literal
		line = file.readline()
		if not line:
			break  # Last literal was at the end of the line
		if line[-1] != '}':
			text.append(line)
			break  # Last literal was in the middle of the line
	return (''.join(text), data)

class IMAP4:
	"""IMAP4rev1 [RFC-3501] implementation."""

	def __init__(self, addr, timeout=60.0, ssl_ctx=None, sock_cls=None):
		"""Open IMAP4 connection.

		Server address may be specified as 'host', 'host:port', or
		('host', port). When the port is omitted it defaults to 143 for non-SSL
		connections and 993 for SSL.

		The default socket timeout is 60 seconds and may be changed with the
		timeout parameter. See socket.settimeout for an explanation of possible
		timeout values. Non-blocking mode (0.0) is not supported, but server
		responses may be obtained in a non-blocking fashion by poll()ing.

		SSL is enabled by passing a valid ssl.SSLContext instance in ssl_ctx
		parameter. Server hostname verification will be performed only if
		ssl_ctx.verify_mode is set to ssl.CERT_REQUIRED. The alternative to
		using SSL is the STARTTLS command, which may be issued after an
		unencrypted connection on port 143 is established and the server
		advertises STARTTLS capability.
		"""
		self.greeting = None   # Greeting received from the server
		self.caps     = ()     # Current server capabilities
		self.new_caps = False  # Set to True when new capabilities are received
		self.readonly = None   # Mailbox read/write status in 'selected' state
		self._sock    = None   # IMAP4Socket instance
		self._state   = None   # Connection state (one of _all_states)

		self.cmds  = OrderedDict()  # Commands in progress
		self.queue = OrderedDict()  # Unclaimed response queue

		# Convert addr to a (host, port) tuple
		if isinstance(addr, str):
			if ':' in addr:
				addr, port = addr.split(':', 1)
			else:
				port = 993 if ssl_ctx else 143
			addr = (addr, int(port))

		# Generate a random tag name
		alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
		self._tag_name = ''.join(random.choice(alpha) for i in range(5))
		self._tag_seq  = lambda ctr=itertools.count(1): str(next(ctr))
		_debug1('New IMAP4 connection [tag={}]', self._tag_name)

		# Valid response tag prefixes for this connection
		self._rsp_tags = ('* ', '+ ', self._tag_name)

		# Connect
		try:
			self._open(addr, timeout, ssl_ctx, sock_cls)
		except Exception:
			self._close()
			raise

	def __enter__(self):
		"""Context manager entrance."""
		return self

	def __exit__(self, exc_type, exc_val, exc_tb):
		"""Automatic logout on exit."""
		self.logout()

	def __call__(self, name, *args, binary=False):
		"""Send a complete command to the server.

		The command name must be specified separately from the remaining
		arguments. 'UID' is considered a command prefix, so both parts must be
		passed together separated by a single space (e.g. imap('UID FETCH', ...)
		instead of imap('UID', 'FETCH', ...)).

		The remaining arguments may be passed in a single string or listed
		separately, in which case they will be joined by spaces (with proper
		handling for parentheses). Individual command classes may impose
		additional restrictions. It is up to the caller to quote and encode
		values where necessary. Bytes objects are transmitted as literals. Octet
		counts are calculated automatically. None is converted to 'NIL'.

		Setting binary to True is an indication that bytes objects should be
		sent using literal8 syntax of [RFC-3516].

		This method returns an IMAP4Command instance as soon as all command
		parts are sent to the server, without waiting for a response. Multiple
		concurrent commands may be issued, but it is up to the caller to follow
		the ambiguity rules described in [RFC-3501] section 5.5. Some commands,
		such as STARTTLS, may not run in parallel with any others. A
		ProtocolError will be raised if an attempt is made to run such commands
		while others are in progress.
		"""
		if self._state == 'logout':
			raise IMAP4Error('connection is closed')  # or is being closed

		# Create new command instance
		tag = self._tag_name + self._tag_seq()
		cmd = IMAP4Command(self, tag, name, args)
		_debug3('>>> {}({})', name, tag)

		# Send the initial text
		parts = cmd._parts(binary)
		self._sock.writeline(next(parts), False)
		self.cmds[tag] = cmd  # Circular reference until the command is finished

		# Send literals
		try:
			wait = 'LITERAL+' not in self.caps
			for data, text in zip(parts, parts):
				if wait:
					# Wait for a continuation request
					self._sock.flush()
					rsp = self._wait(cmd, True)
					if rsp.type != 'continue':
						break
				else:
					# Poll for server interrupt when using LITERAL+
					while self.poll():
						if cmd.result:
							rsp = cmd.result
							break
				self._sock.write(data)
				self._sock.writeline(text, False)
			else:
				# All text and data sent successfully
				self._sock.flush()
				return cmd
		except Exception:
			self.cmds.pop(tag, None)  # Break circular reference on error
			raise

		exc = NO if rsp.status == 'NO' else BAD
		raise exc('server refused literal data', rsp.info, rsp, cmd)

	def __iter__(self):
		"""Server response iterator."""
		return self

	def __next__(self):
		"""Get the next server response.

		All responses are returned to the caller in the order they are received.
		Status, data, and command completion responses first undergo some
		additional processing and error-checking.

		Data and status responses are added to the queue of whichever command
		claims them (_is_data method returns True). Unclaimed responses are
		added to the common queue, which is typically consumed by NOOP.
		"""
		while self._sock and not self._sock.eof:
			try:
				text, data = _readline(self._sock, self._rsp_tags)
			except Exception:
				# The most likely exception here is socket.timeout, but any
				# exception raised while reading from the socket may have caused
				# some data loss or left the buffer in an inconsistent state. As
				# a result, the socket must be closed. See issue #7322.
				self._close()
				raise

			rsp = IMAP4Response(text, data)
			if rsp.type == 'continue':
				return rsp
			if rsp.dtype == 'CAPABILITY':
				self._update_caps(rsp)
			if rsp.status:
				if rsp.type == 'done':
					try:
						self._check_status(rsp)
						return rsp
					finally:
						self._done(rsp)
				self._check_status(rsp)

			# Try to find the 'status' or 'data' response owner
			for cmd in self.cmds.values():
				if cmd._is_data(rsp):
					cmd.queue.append(rsp)
					return rsp

			# Add unclaimed responses to the common queue
			self.queue[rsp.seq] = rsp
			return rsp
		raise StopIteration

	def poll(self):
		"""Poll for a server response.

		This method checks if the first line of the next server response is
		available. If not, None is returned immediately without blocking.
		Otherwise, execution is blocked until the rest of the response is
		received (if it contained any literals) and an IMAP4Response instance is
		returned.
		"""
		try:
			if self._sock.peekline() is None:
				if self._sock.eof:
					raise IMAP4Error('connection is closed')
				return None
		except Exception:
			self._close()
			raise
		return next(self, None)

	def block(self, timeout=None):
		"""Block execution until a complete server response is available.

		If a timeout is specified in seconds, this method may return before the
		timeout expires, even if a complete response is not yet available. It is
		up to the caller to check the exact amount of time that was spent
		waiting.
		"""
		rsp = self.poll()
		while not rsp:
			if self._sock.block(timeout):
				rsp = self.poll()
			if timeout is not None:
				break
		return rsp

	def claim(self, rsp):
		"""Claim a response from the common queue."""
		return self.queue.pop(rsp.seq, rsp)

	def defer(self, rsp):
		"""Return response to the common queue."""
		queue   = self.queue
		new_seq = rsp.seq
		max_seq = next(reversed(queue), new_seq)
		queue[new_seq] = rsp

		# Preserve response order
		if new_seq < max_seq:
			older = [seq for seq in queue if seq > new_seq]
			for seq in older:
				queue.move_to_end(seq)

	def wait_all(self):
		"""Wait for all active commands to finish."""
		for cmd in self.cmds.values():
			if cmd.name == 'IDLE':  # Waiting for IDLE causes a deadlock
				raise RuntimeError("cannot wait for 'IDLE' to finish")
			_debug3('Waiting for {}({}) to finish...', cmd.full_name, cmd.tag)
			self._wait(cmd)

	#
	# 6.1 Client Commands - Any State
	#

	def capability(self):
		"""Request current server capabilities.

		Capabilities are updated automatically when the connection is first
		established and after each successful LOGIN, AUTHENTICATE, STARTTLS, and
		COMPRESS command.

		See the following website for a listing of CAPABILITY responses returned
		by various IMAP4 servers: http://www.nasmail.org/docs/imap_servers.shtml
		"""
		self.new_caps = False
		cmd = self('CAPABILITY').wait()
		if self.new_caps:
			return cmd
		raise ProtocolError('capabilities not received')  # Should never happen

	def noop(self, *, wait=True):
		"""Issue the NOOP command."""
		cmd = self('NOOP')
		return cmd.wait() if wait else cmd

	def logout(self, graceful=True):
		"""Issue the LOGOUT command and close the connection."""
		try:
			if self._sock and self._state != 'logout':
				if graceful:
					self.wait_all()
					return self('LOGOUT').wait()
				else:
					self('LOGOUT')
			return None
		finally:
			self._close()

	#
	# 6.2. Client Commands - Not Authenticated State
	#

	def starttls(self, ssl_ctx):
		"""Issue STARTTLS command and perform TLS negotiation.

		This method waits for command completion and uses the provided
		SSLContext object to negotiate link encryption. An exception is raised
		if the server rejects the command or if TLS negotiation fails. In the
		second case, the connection is automatically closed.

		A CAPABILITY command is always issued after successful TLS negotiation
		as required by [RFC-3501] section 6.2.1.
		"""
		if self._sock.encrypted:
			raise RuntimeError('SSL or TLS is already enabled')
		cmd = self('STARTTLS').wait()
		try:
			_debug1('Performing TLS negotiation...')
			self._sock.starttls(ssl_ctx)
			self.capability()
		except Exception:
			self._close()
			raise
		return cmd

	def authenticate(self, mech, ir=None, cr=None):
		"""Perform SASL authentication.

		Authentication is performed by specifying a mechanism name and 'ir'
		and/or 'cr' parameters. If specified, 'ir' must be a bytes object
		representing the initial client response, which may be empty. It will be
		encoded to base64 and sent after the first continuation request, or with
		the initial command if SASL-IR [RFC-4959] is advertised.

		Subsequent challenge-response interactions (if any) are handled through
		the 'cr' parameter, which must be a callable object that accepts a
		single bytes argument containing the decoded server challenge. It must
		return a bytes object representing the response to proceed with
		authentication or None to abort (causing an exception to be raised).
		Base64 encoding/decoding is done automatically.

		If authentication is successful and the server did not provide new
		capabilities, the CAPABILITY command is issued automatically.
		"""
		if cr and not callable(cr):
			raise TypeError('authentication object is not callable')

		args = ()
		if ir is not None and 'SASL-IR' in self.caps:
			_debug2('Using SASL-IR for initial authentication request...')
			args = (b64encode(ir).decode('ascii') if ir else '=',)
			ir   = None

		self.new_caps = False
		cmd = self('AUTHENTICATE', mech, *args)

		while cr or ir is not None:
			rsp = self._wait(cmd, True)
			if rsp.type != 'continue':
				break
			try:
				ans = cr(rsp.info) if ir is None else ir
				if ans is None:
					raise IMAP4Error('authentication aborted by the client')
				ans = b64encode(ans).decode('ascii')
				ir  = None
			except Exception:
				self._sock.writeline('*')  # Send abort notification
				self._wait(cmd)
				raise
			self._sock.writeline(ans)  # Send challenge response
		return self._wait_caps(cmd)

	def login(self, username, password, allow_cleartext=False):
		"""Perform plaintext authentication.

		Username and password may be str or bytes objects. Bytes objects are
		sent as literals. Strings are either quoted and sent in a single
		transmission (if they contain only US-ASCII characters), or encoded as
		UTF-8 and sent as literals.

		LOGIN authentication is not permitted when LOGINDISABLED capability is
		advertised by the server, or when the link is not encrypted and
		allow_cleartext is set to False (default).

		If authentication is successful and the server did not provide new
		capabilities, the CAPABILITY command is issued automatically.
		"""
		encrypted = self._sock.encrypted
		if not (encrypted or allow_cleartext):
			raise IMAP4Error("'LOGIN' not allowed over an unencrypted link")
		self.new_caps = False
		cmd = self('LOGIN', qstr_or_lit(username), qstr_or_lit(password))
		if not encrypted:
			_debug1('WARNING: USERNAME AND PASSWORD SENT UNENCRYPTED')
		return self._wait_caps(cmd)

	#
	# 6.3. Client Commands - Authenticated State
	#

	def select(self, mbox, readonly=False):
		"""Open a mailbox in read-write or read-only mode.

		Mailbox name is automatically quoted and encoded as modified UTF-7.

		The readonly parameter determines whether SELECT or EXAMINE is used to
		open the mailbox. Setting readonly to None prevents an exception from
		being thrown if the server chooses to open the mailbox in read-only mode
		after a SELECT command.
		"""
		name = 'EXAMINE' if readonly else 'SELECT'
		cmd  = self(name, qstr_iutf7(mbox)).wait()
		if readonly is not None and self.readonly != readonly:
			raise AccessModeError('incorrect mailbox access mode')
		return cmd

	def create(self, mbox, *, wait=True):
		"""Create new mailbox."""
		cmd = self('CREATE', qstr_iutf7(mbox))
		return cmd.wait() if wait else cmd

	def delete(self, mbox, *, wait=True):
		"""Delete an existing mailbox."""
		cmd = self('DELETE', qstr_iutf7(mbox))
		return cmd.wait() if wait else cmd

	def rename(self, old_mbox, new_mbox, *, wait=True):
		"""Rename an existing mailbox."""
		cmd = self('RENAME', qstr_iutf7(old_mbox), qstr_iutf7(new_mbox))
		return cmd.wait() if wait else cmd

	def subscribe(self, mbox, *, wait=True):
		"""Subscribe to a mailbox."""
		cmd = self('SUBSCRIBE', qstr_iutf7(mbox))
		return cmd.wait() if wait else cmd

	def unsubscribe(self, mbox, *, wait=True):
		"""Unsubscribe from a mailbox."""
		cmd = self('UNSUBSCRIBE', qstr_iutf7(mbox))
		return cmd.wait() if wait else cmd

	def list(self, ref='', mbox='%', *, wait=True):
		"""List mailboxes on the server.

		See [RFC-3501] sections 6.3.8 and 7.2.2, and [RFC-2683] sections
		3.2.1.1, 3.2.2, 3.4.7, 3.4.9, and 3.4.10 for detailed information about
		the LIST command.
		"""
		cmd = self('LIST', qstr_iutf7(ref), qstr_iutf7(mbox))
		return cmd.wait() if wait else cmd

	def lsub(self, ref='', mbox='%', *, wait=True):
		"""List subscribed mailboxes."""
		cmd = self('LSUB', qstr_iutf7(ref), qstr_iutf7(mbox))
		return cmd.wait() if wait else cmd

	def status(self, mbox, *attrs, wait=True):
		"""Get mailbox status.

		Valid attributes: MESSAGES, RECENT, UIDNEXT, UIDVALIDITY, UNSEEN

		All valid attributes are requested by default.
		"""
		if not attrs:
			attrs = 'MESSAGES RECENT UIDNEXT UIDVALIDITY UNSEEN'
		else:
			attrs = ' '.join(attrs)
		cmd = self('STATUS', qstr_iutf7(mbox), '(', attrs, ')')
		return cmd.wait() if wait else cmd

	def append(self, mbox, data, flags=None, idate=None, *, wait=True):
		"""Append new message to a mailbox.

		Message data will be encoded as UTF-8 if it is not already a bytes
		object.

		Flags is an optional sequence of flags which should be set for this
		message. The '\Recent' flag is ignored.

		Internal date may be specified in the idate parameter as a string or a
		Unix timestamp.
		"""
		return self.multiappend(mbox, ((data, flags, idate),), wait=wait)

	#
	# 6.4. Client Commands - Selected State
	#

	def check(self, *, wait=True):
		"""Perform server-specific mailbox checkpoint tasks."""
		cmd = self('CHECK')
		return cmd.wait() if wait else cmd

	def close(self, expunge=True):
		"""Close the current mailbox.

		When expunge is set to True (default), the CLOSE command is issued,
		which permanently removes all messages with the \Deleted flag set.

		Otherwise, UNSELECT [RFC-3691], or its (failed) EXAMINE equivalent, is
		used to close the current mailbox without expunging deleted messages.
		"""
		if expunge:
			return self('CLOSE').wait()
		if 'UNSELECT' in self.caps:
			return self('UNSELECT').wait()
		return self('EXAMINE', '__NONEXISTENT_MAILBOX_507589200__').wait('NO')

	def expunge(self, uids=None, *, wait=True):
		"""Permanently remove messages with the \Deleted flag set.

		The uids parameter requires UIDPLUS capability and may be used to limit
		which messages get expunged by specifying a sequence set of UIDs in a
		manner similar to fetch, store, and copy commands.
		"""
		if uids is None:
			cmd = self('EXPUNGE')
		else:
			cmd = self('UID EXPUNGE', str(self._seqset(uids)))
		return cmd.wait() if wait else cmd

	def search(self, *spec, wait=True, uid=False):
		"""Search for messages in the current mailbox.

		This method expects the caller to properly quote and encode search
		criteria using UTF-8 encoding. Unencoded parameters must be valid
		US-ASCII strings.
		"""
		name = 'UID SEARCH' if uid else 'SEARCH'
		cmd  = self(name, 'CHARSET UTF-8', *spec)
		return cmd.wait() if wait else cmd

	def fetch(self, seqset, *attrs, wait=True, uid=False):
		"""Fetch message data or attributes.

		The seqset parameter specifies one or more message sequence numbers
		(SNs) or UIDs, depending on the value of the uid parameter. This may be
		a string (e.g. '1,5,10:*'), an int, or any python sequence containing
		ints (e.g. IMAP4SeqSet).

		Specifying a string will prevent the command from filtering out FETCH
		responses that do not belong to it. This behavior is necessary when
		requesting attributes for '*', since the SN and UID of the last message
		are unknown.

		A list of all valid attributes is available in [RFC-3501] section 6.4.5.
		See [RFC-2683] section 3.4.4 for important information about responses
		to the FETCH command.
		"""
		name = 'UID FETCH' if uid else 'FETCH'
		seq  = self._seqset(seqset)
		cmd  = self(name, str(seq), '(', ' '.join(attrs), ')')
		if isinstance(seq, IMAP4SeqSet):
			cmd.seqset = seq
		return cmd.wait() if wait else cmd

	def store(self, seqset, attr, *vals, wait=True, uid=False):
		"""Set message flags.

		See fetch() for details on seqset parameter.
		"""
		name = 'UID STORE' if uid else 'STORE'
		seq  = self._seqset(seqset)
		cmd  = self(name, str(seq), attr, '(', ' '.join(vals), ')')
		if isinstance(seq, IMAP4SeqSet):
			cmd.seqset = seq
		return cmd.wait() if wait else cmd

	def copy(self, seqset, mbox, *, wait=True, uid=False):
		"""Copy message(s) from the current mailbox to another one."""
		name = 'UID COPY' if uid else 'COPY'
		cmd  = self(name, str(self._seqset(seqset)), qstr_iutf7(mbox))
		return cmd.wait() if wait else cmd

	#
	# [RFC-2087] IMAP4 QUOTA extension
	#

	def setquota(self, root, *limits, wait=True):
		"""Set quota limits on the given root."""
		limits = ' '.join(map(str, limits))
		cmd = self('SETQUOTA', qstr_or_lit(root), '(', limits, ')')
		return cmd.wait() if wait else cmd

	def getquota(self, root, *, wait=True):
		"""Get quota limits for the given root."""
		cmd = self('GETQUOTA', qstr_or_lit(root))
		return cmd.wait() if wait else cmd

	def getquotaroot(self, mbox, *, wait=True):
		"""Get the quota root name of the given mailbox."""
		cmd = self('GETQUOTAROOT', qstr_iutf7(mbox))
		return cmd.wait() if wait else cmd

	#
	# [RFC-2177] IMAP4 IDLE command
	#

	def idle(self):
		"""Go into idle mode, permitting real-time server status updates.

		The returned IMAP4Command is a context manager object which will
		terminate itself automatically when existing from the 'with' context.

		While active, the command claims all received responses, but the
		__iter__ method does not block as it does for all other commands (doing
		so would risk raising the socket.timeout exception, which would close
		the connection). Instead, the caller should use IMAP4 poll() or block()
		methods to periodically check for new responses.
		"""
		cmd = self('IDLE')
		rsp = self._wait(cmd, True)
		if rsp.type == 'continue':
			_debug2('Connection is idling...')
			return cmd
		cmd.check('Worse things happen at sea, you know.')

	#
	# [RFC-2193] IMAP4 Mailbox Referrals
	#

	def rlist(self, ref='', mbox='%', *, wait=True):
		"""List local and remote mailboxes.

		See list() for additional information.
		"""
		cmd = self('RLIST', qstr_iutf7(ref), qstr_iutf7(mbox))
		return cmd.wait() if wait else cmd

	def rlsub(self, ref='', mbox='%', *, wait=True):
		"""List subscribed local and remote mailboxes."""
		cmd = self('RLSUB', qstr_iutf7(ref), qstr_iutf7(mbox))
		return cmd.wait() if wait else cmd

	#
	# [RFC-2195] IMAP/POP AUTHorize Extension
	#

	def login_cram_md5(self, username, password):
		"""CRAM-MD5 authentication."""
		u  = username.encode() if isinstance(username, str) else username
		p  = password.encode() if isinstance(password, str) else password
		cr = lambda c: u + b' ' + hmac.new(p, c).hexdigest().encode('ascii')
		return self.authenticate('CRAM-MD5', cr=cr)

	#
	# [RFC-2342] IMAP4 Namespace
	#

	def namespace(self, *, wait=True):
		"""Get a list of available namespaces."""
		cmd = self('NAMESPACE')
		return cmd.wait() if wait else cmd

	#
	# [RFC-2971] IMAP4 ID extension
	#

	def id(self, info=None, *, wait=True):
		"""Send client ID to the server and get the server ID in response.

		This method accepts an optional dictionary containing one or more items,
		where the key is a valid field name as defined in [RFC-2971] section
		3.3, and value is the corresponding field value.
		"""
		if info:
			args = ['(']
			for k, v in info.items():
				args.append(qstr_or_lit(k))
				args.append('NIL' if v is None else qstr_or_lit(v))
			args.append(')')
		else:
			args = ('NIL',)
		cmd = self('ID', *args)
		return cmd.wait() if wait else cmd

	#
	# [RFC-3502] IMAP MULTIAPPEND
	#

	def multiappend(self, mbox, msgs, *, wait=True, binary=False):
		"""Append multiple new messages to a mailbox.

		The msgs parameter must be a sequence of tuples in the format (data,
		flags, idate), where flags and/or idate may be set to None. See append()
		for an explanation of each item.
		"""
		args  = [qstr_iutf7(mbox)]
		nmsgs = 0
		for data, flags, idate in msgs:
			# Perform MULTIAPPEND check only for the second message
			if nmsgs == 1 and CHECK_CAPS and 'MULTIAPPEND' not in self.caps:
				raise IMAP4Error('MULTIAPPEND capability is not available')
			if flags is not None:
				flags = ' '.join(f for f in flags if f.lower() != '\\recent')
				if flags:
					args.extend(('(', flags, ')'))
			if idate is not None:
				if isinstance(idate, int):
					idate = unix2idate(idate)
				args.append(qstr(idate))
			args.append(data if isinstance(data, _lit_types) else data.encode())
			nmsgs += 1
		cmd = self('APPEND', *args, binary=binary)
		return cmd.wait() if wait else cmd

	#
	# [RFC-4314] IMAP4 Access Control List (ACL) Extension
	#

	def setacl(self, mbox, ident, rights, *, wait=True):
		"""Change identifier rights on the specified mailbox."""
		cmd = self('SETACL', qstr_iutf7(mbox), qstr_or_lit(ident),
		           qstr_or_lit(rights))
		return cmd.wait() if wait else cmd

	def deleteacl(self, mbox, ident, *, wait=True):
		"""Remove all identifier rights from the specified mailbox."""
		cmd = self('DELETEACL', qstr_iutf7(mbox), qstr_or_lit(ident))
		return cmd.wait() if wait else cmd

	def getacl(self, mbox, *, wait=True):
		"""Get mailbox access control list."""
		cmd = self('GETACL', qstr_iutf7(mbox))
		return cmd.wait() if wait else cmd

	def listrights(self, mbox, ident, *, wait=True):
		"""List mailbox rights that can be granted to the identifier."""
		cmd = self('LISTRIGHTS', qstr_iutf7(mbox), qstr_or_lit(ident))
		return cmd.wait() if wait else cmd

	def myrights(self, mbox, *, wait=True):
		"""List mailbox rights of current user."""
		cmd = self('MYRIGHTS', qstr_iutf7(mbox))
		return cmd.wait() if wait else cmd

	#
	# [RFC-4978] The IMAP COMPRESS Extension
	#

	def compress(self, method='DEFLATE', level=3):
		"""Enable data compression."""
		if method != 'DEFLATE':
			raise ValueError('{!a} compression is not supported'.format(method))
		if self._sock.compressed:
			raise RuntimeError('compression is already enabled')
		cmd = self('COMPRESS', method).wait()
		try:
			_debug1('Enabling DEFLATE compression...')
			self._sock.compress_deflate(level)
			self.capability()  # Helps to detect errors with compression
		except Exception:
			self._close()
			raise
		return cmd

	#
	# [RFC-5161] The IMAP ENABLE Extension
	#

	def enable(self, *caps):
		"""Enable the specified capabilities."""
		return self('ENABLE', *caps).wait()

	#
	# [RFC-5256] SORT and THREAD Extensions
	#

	def sort(self, sort, *search, wait=True, uid=False):
		"""Sort messages according to the sort and search criteria.

		See search() for additional information about the search criteria.
		"""
		if not isinstance(sort, str):
			sort = '(' + ' '.join(sort) + ')'
		if not search:
			search = ('ALL',)
		name = 'UID SORT' if uid else 'SORT'
		cmd  = self(name, sort, 'UTF-8', *search)
		return cmd.wait() if wait else cmd

	def thread(self, method, *search, wait=True, uid=False):
		"""Group messages by threads.

		See search() for additional information about the search criteria.
		"""
		if not search:
			search = ('ALL',)
		name = 'UID THREAD' if uid else 'THREAD'
		cmd  = self(name, method, 'UTF-8', *search)
		return cmd.wait() if wait else cmd

	#
	# [RFC-5464] The IMAP METADATA Extension
	#

	def getmetadata(self, mbox, *entires, **opts):
		"""Get server or mailbox metadata."""
		wait    = opts.pop('wait', True)
		mbox    = qstr_iutf7(mbox)
		entires = ' '.join(map(qstr, entires))
		if opts:
			opts = ' '.join(map(str, ungroup(opts.items())))
			cmd  = self('GETMETADATA', mbox, '(', opts, ')', '(', entires, ')')
		else:
			cmd = self('GETMETADATA', mbox, '(', entires, ')')
		return cmd.wait() if wait else cmd

	def setmetadata(self, mbox, *entires, wait=True):
		"""Set server or mailbox metadata."""
		items   = tuple(group(entires))
		entires = ['(']
		for k, v in items:
			entires.extend((qstr(k), 'NIL' if v is None else qstr_or_lit(v)))
		entires.append(')')
		cmd = self('SETMETADATA', qstr_iutf7(mbox), *entires)
		return cmd.wait() if wait else cmd

	#
	# Non-standard commands
	#

	def proxyauth(self, username):
		"""Perform proxy authentication to impersonate another user."""
		return self('PROXYAUTH', qstr_or_lit(username)).wait()

	def xlist(self, ref='', mbox='%', *, wait=True):
		"""Gmail XLIST command (http://code.google.com/apis/gmail/imap/)."""
		cmd = self('XLIST', qstr_iutf7(ref), qstr_iutf7(mbox))
		return cmd.wait() if wait else cmd

	#
	# --- End of Commands ---
	#

	@property
	def state(self):
		"""Current connection state."""
		return self._state

	@state.setter
	def state(self, newstate):
		oldstate = self._state
		if newstate != oldstate and oldstate != 'logout':
			if newstate not in _all_states:
				raise ValueError('invalid state {!a}'.format(value))
			if newstate == '!auth' and oldstate:
				raise ValueError('invalid state change')
			_debug2('State change: {} -> {}', oldstate, newstate)
			self.readonly = False if newstate == 'selected' else None
			self._state = newstate

	@property
	def queued(self):
		"""Common queue iterator."""
		return self.queue.values()

	def _open(self, addr, timeout, ssl_ctx, sock_cls):
		"""Create connection socket."""
		if not sock_cls:
			sock_cls = IMAP4Socket
		self._sock = sock_cls(addr, timeout, ssl_ctx)
		self._read_greeting()
		if not self.caps:
			self.capability()
		if 'IMAP4REV1' not in self.caps:
			raise ProtocolError('not an IMAP4rev1 server')

	def _close(self):
		"""Close connection socket."""
		if self._sock:
			try:
				self._sock.close()
			finally:
				self._sock = None
				self.caps  = ()
				self.state = 'logout'
				self.cmds.clear()

	def _read_greeting(self):
		"""Read server greeting after the connection is established."""
		rsp = self.claim(next(self))
		if rsp.status not in ('OK', 'PREAUTH'):  # BYE is handled in __next__
			raise ProtocolError('invalid server greeting', rsp.text)
		_debug1('Server greeting: {} {}', rsp.status, rsp.info)
		self.greeting = rsp.info
		self.state = 'auth' if rsp.status == 'PREAUTH' else '!auth'
		return rsp

	def _update_caps(self, rsp):
		"""Update server capability cache."""
		self.caps = set(map(str.upper, rsp[1:]))  # Must be case-insensitive
		self.new_caps = True
		if _debug_level >= 2:
			_debug2('Capabilities: {}', ' '.join(sorted(self.caps)))

	def _check_status(self, rsp):
		"""Check a status response (tagged or untagged) for errors."""
		# Show server alerts (should also be done outside of the library)
		if rsp.dtype == 'ALERT':
			_debug1('SERVER ALERT: {}', rsp.info)

		# An unexpected BYE response closes the connection
		if rsp.status == 'BYE':
			if self._state != 'logout':
				self._close()
				raise BYE('server closed the connection', rsp.info, rsp)
			return

		if self._state == 'selected':
			# Raise an exception on unexpected access mode changes
			if (rsp.dtype == 'READ-ONLY' and not self.readonly) or \
			   (rsp.dtype == 'READ-WRITE' and self.readonly):
				msg = 'mailbox access mode changed to ' + rsp.dtype.lower()
				raise AccessModeError(msg, rsp.info)

			# Raise an exception on unexpected changes in UIDVALIDITY
			if rsp.dtype == 'UIDVALIDITY':
				raise UIDValidityError('uidvalidity has changed', rsp.info)

		# An untagged BAD response terminates all active commands
		if rsp.status == 'BAD' and rsp.tag == '*':
			_debug3('Untagged BAD response, terminating all commands')
			cmds = tuple(self.cmds.values())
			self.cmds.clear()
			for cmd in cmds:
				cmd.result = rsp
				cmd._done(rsp)
			raise BAD(rsp.info, response=rsp)

	def _done(self, rsp):
		"""Perform command-specific completion tasks."""
		cmd = self.cmds.pop(rsp.tag, None)  # Break circular reference
		if not cmd:
			_debug3('Completion of an unknown command: {}', rsp.text)
			return
		if _debug_level >= 3:
			name = cmd.full_name
			_debug3('Responses: {} {}, {} unclaimed', len(cmd.queue), name,
			        len(self.queue))
			_debug3('<<< {}({})', name, rsp.text)
		cmd.result = rsp
		cmd._done(rsp)

	def _wait(self, cmd, expect_continue=False):
		"""Wait for command completion response or continuation request."""
		if cmd.result:
			return cmd.result  # Command is already finished
		for rsp in self:
			if cmd.result:
				return cmd.result
			if rsp.type == 'continue':
				if expect_continue:
					return rsp
				raise ProtocolError('unexpected continuation request')
		raise ProtocolError('connection closed while waiting for response')

	def _wait_caps(self, cmd, *expect):
		"""Wait for command completion and update capabilities.

		The caller must reset self.new_caps to False. New capabilities are
		requested only if the server doesn't send them automatically.
		"""
		cmd.wait(*expect)
		if not self.new_caps:
			self.capability()
		return cmd

	def _seqset(self, seqset):
		"""Try to create an IMAP4SeqSet instance from the given sequence set."""
		if isinstance(seqset, IMAP4SeqSet):
			return seqset
		if isinstance(seqset, int):
			return IMAP4SeqSet((seqset,))
		if not isinstance(seqset, str):
			return IMAP4SeqSet(seqset)
		if seqset.isdigit():
			return IMAP4SeqSet((int(seqset),))

		# Converting any other string to IMAP4SeqSet may be impractical (e.g.
		# '1:100000000') or impossible (e.g. '1:*' or '$'), so leave that
		# decision up to the caller.
		return seqset

#
###  Commands  #################################################################
#

class IMAP4CommandType(type):
	"""IMAP4Command metaclass."""

	registry = {}  # Dictionary of command names and associated handlers

	def __new__(mcs, name, bases, attrs):
		# Require all commands to have a '__slots__' attribute
		attrs.setdefault('__slots__', ())

		# Use class name when the 'names' attribute is not specified
		if 'names' not in attrs and name == name.upper():
			attrs['names'] = (name,)

		# Create and register new command class
		cls = type.__new__(mcs, name, bases, attrs)
		mcs.registry.update((name, cls) for name in cls.names)
		return cls

class IMAP4Command(metaclass=IMAP4CommandType):
	"""IMAP4 command base class."""

	__slots__ = ('imap', 'tag', 'name', 'args', 'uid', 'queue', 'result')

	state = _all_states  # State(s) in which this command is valid
	excl  = False        # Command requires exclusive connection access
	caps  = ()           # Capabilities required by this command
	names = ()           # Command names handled by this class
	dtype = ()           # Data types claimed by this command

	def __new__(cls, imap, tag, name, args):
		"""Create and initialize new command instance."""
		# Select which command class to instantiate
		if cls is IMAP4Command:
			cls = IMAP4CommandType.registry.get(name)
			if not cls:
				raise ValueError('unknown command {!a}'.format(name))
			if cls.__new__ is not IMAP4Command.__new__:
				return cls.__new__(cls, imap, tag, name, args)

		# Check connection state
		if imap._state not in cls.state and CHECK_STATE:
			msg = '{!a} is not valid in {!a} state'.format(name, imap._state)
			raise ProtocolError(msg)

		# Check for exclusive access (LOGOUT is always allowed)
		if imap.cmds and name != 'LOGOUT':
			if cls.excl:
				msg = '{!a} requires exclusive connection access'.format(name)
				raise ProtocolError(msg)
			if next(iter(imap.cmds.values())).excl:
				msg = 'another command has exclusive connection access'
				raise ProtocolError(msg)

		# Initialize command instance
		self = object.__new__(cls)
		uid  = name.startswith('UID ')
		if uid:
			name = name[4:]

		self.imap   = imap     # Connection that created this command
		self.tag    = tag      # Command tag
		self.name   = name     # Command name without the UID prefix
		self.args   = args     # Arguments as passed to IMAP4.__call__
		self.uid    = uid      # UID prefix flag
		self.queue  = deque()  # Data queue
		self.result = None     # Command completion IMAP4Response

		# Check server capabilities
		if CHECK_CAPS and not self._check_caps(imap, name, args):
			raise IMAP4Error('{!a} is disabled or not supported'.format(name))
		return self

	def __str__(self):
		attrs = ', '.join(map('{0[0]}={0[1]!a}'.format, (
			('tag',  self.tag),
			('uid',  self.uid),
			('done', self.result is not None),
			('qlen', len(self.queue)),
			('args', self.args)
		)))
		return '{}({})'.format(self.name, attrs)

	def __iter__(self):
		"""Iterate over data responses for this command."""
		queue = self.queue
		while queue:
			yield queue.popleft()
		while not self.result and next(self.imap, None):
			while queue:
				yield queue.popleft()

	def wait(self, *expect):
		"""Wait for command completion.

		See check() for details on the expect parameter.
		"""
		if not self.result:
			self.imap._wait(self)
		self.check(*expect)
		return self

	def check(self, *expect):
		"""Check command completion status.

		One or more of the three possible completion codes (OK, NO, BAD) may be
		passed as arguments to this method. An exception will be raised if the
		command is completed with a status code other than those listed.
		Omitting all codes is equivalent to specifying 'OK'.
		"""
		if not self.result:
			raise IMAP4Error('command is not finished')
		rs = self.result.status
		if (not expect and rs != 'OK') or (expect and rs not in expect):
			exc = NO if rs == 'NO' else BAD if rs == 'BAD' else OK
			raise exc(self.result.info, response=self.result, command=self)

	def defer(self, queue=None):
		"""Send queued responses to another queue.

		By default, all responses are sent to the common queue of the parent
		IMAP4 instance. Response order is preserved only if the destination
		queue is an OrderedDict.
		"""
		if queue is None:
			queue = self.imap.queue
		if isinstance(queue, OrderedDict):
			reorder = len(queue) > 0
			queue.update((rsp.seq, rsp) for rsp in self.queue)
			if reorder:
				# Sorting seems to be faster than merging for short queues
				move_to_end = queue.move_to_end
				for seq in sorted(queue):
					move_to_end(seq)
		else:
			queue.extend(self.queue)
		self.queue.clear()

	@property
	def full_name(self):
		"""Full command name, including the UID prefix."""
		return 'UID ' + self.name if self.uid else self.name

	def _check_caps(self, imap, name, args):
		"""Check server capabilities before sending the command.

		This method should return True (default) if the command may be sent or
		False if it is disabled or not supported by the server.
		"""
		return all(cap in imap.caps for cap in self.caps)

	def _parts(self, binary=False):
		"""Generator of assembled command parts.

		The first yielded item is always the initial command text starting with
		the tag. If the command contains any literals, the generator will
		continue yielding alternating data/text values, with the octet counts at
		the end of each preceding text string, until the entire command is
		consumed. If a literal appears at the end of the command, the last text
		string will be empty to indicate a CRLF sequence.
		"""
		SP   = ' '
		text = [self.tag, SP, self.full_name]
		SOC  = '~{' if binary and 'BINARY' in self.imap.caps else '{'
		EOC  = '+}' if 'LITERAL+' in self.imap.caps else '}'
		for arg in self.args:
			if isinstance(arg, _lit_types):
				text.extend((SP, SOC, str(len(arg)), EOC))
				yield ''.join(text)
				yield arg
				text = []
				SP   = ' '
			else:
				if arg is None:
					arg = 'NIL'
				elif arg[0] == ')':  # No space before ')'
					SP = ''
				text.extend((SP, arg))
				SP = '' if arg[-1] == '(' else ' '  # No space after '('
		yield ''.join(text)

	def _is_data(self, rsp):
		"""Check if the given response contains data for this command.

		If this method returns True, the response will be append to this
		command's queue. Otherwise, if no other command claims this response, it
		will be added to the common queue managed by IMAP4 instance.
		"""
		return rsp.dtype == self.name or rsp.dtype in self.dtype

	def _done(self, rsp):
		"""Command completion notification.

		The response may be untagged if the server sent a BAD response without
		indicating which command caused it. In this case, all active commands
		are given the same response instance and are terminated. See [RFC-3501]
		section 7.1.3.
		"""

#
# 6.1 Client Commands - Any State
#

class CAPABILITY(IMAP4Command):
	pass

class NOOP(IMAP4Command):
	def __iter__(self):
		"""Common queue iterator."""
		imap  = self.imap
		queue = imap.queue
		for rsp in map(imap.claim, queue.values()):
			yield rsp
		while not self.result and next(imap, None):
			for rsp in map(imap.claim, queue.values()):
				yield rsp

	def _is_data(self, rsp):
		return False  # NOOP claims only what all other commands have rejected

class LOGOUT(IMAP4Command):
	def __init__(self, imap, tag, name, args):
		imap.state = 'logout'  # Block new commands and expect a BYE response

	def _is_data(self, rsp):
		return rsp.status == 'BYE'

class ID(IMAP4Command):  # [RFC-2971]
	caps = ('ID',)

class COMPRESS(IMAP4Command):  # [RFC-4978]
	excl = True

	def _check_caps(self, imap, name, args):
		return 'COMPRESS=' + args[0].upper() in imap.caps

#
# 6.2. Client Commands - Not Authenticated State
#

_state = ('!auth',)

class STARTTLS(IMAP4Command):
	state = _state
	excl  = True
	caps  = ('STARTTLS',)

	def _done(self, rsp):
		if rsp.status == 'OK':
			self.imap.caps = ()  # New capabilities must be requested

class AuthCmds(IMAP4Command):
	state = _state
	excl  = True
	names = ('AUTHENTICATE', 'LOGIN')
	dtype = ('CAPABILITY',)

	def _check_caps(self, imap, name, args):
		if name == 'AUTHENTICATE':
			return 'AUTH=' + args[0].upper() in imap.caps
		return 'LOGINDISABLED' not in imap.caps

	def _done(self, rsp):
		_debug1('Authentication: {} {}', rsp.status, rsp.info)
		if rsp.status == 'OK':
			self.imap.state = 'auth'

#
# 6.3. Client Commands - Authenticated State
#

_state = ('auth', 'selected')

class SelectCmds(IMAP4Command):
	__slots__ = ('_prev_state',)

	state = _state
	excl  = True
	names = ('SELECT', 'EXAMINE')
	dtype = {'FLAGS', 'EXISTS', 'RECENT', 'UNSEEN', 'PERMANENTFLAGS', 'UIDNEXT',
	         'UIDVALIDITY', 'UIDNOTSTICKY'}

	def __init__(self, imap, tag, name, args):
		# Silent state change to avoid UIDValidityError when issuing SELECT or
		# EXAMINE commands from selected state.
		self._prev_state = imap._state
		imap._state = 'auth'
		imap.queue.clear()

	def _done(self, rsp):
		imap = self.imap
		imap._state = self._prev_state  # Undo silent state change
		if rsp.status == 'OK':
			imap.state = 'selected'
			if rsp.dtype == 'READ-ONLY':
				imap.readonly = True  # Was set to False during state change
				access = rsp.dtype
			else:
				access = 'READ-WRITE'
			_debug1('Mailbox selected: {} ({})', self.args[0], access)
		else:
			if rsp.status == 'NO':
				imap.state = 'auth'
			_debug1('Mailbox selection failed: {} {}', rsp.status, rsp.info)

class MailboxCmds(IMAP4Command):
	state = _state
	names = ('CREATE', 'DELETE', 'RENAME', 'SUBSCRIBE', 'UNSUBSCRIBE', 'LIST',
	         'LSUB', 'STATUS', 'APPEND')

class QuotaCmds(IMAP4Command):  # [RFC-2087]
	state = _state
	caps  = ('QUOTA',)
	names = ('SETQUOTA', 'GETQUOTA', 'GETQUOTAROOT')
	dtype = {'QUOTA', 'QUOTAROOT'}

class IDLE(IMAP4Command):  # [RFC-2177]
	state = _state
	excl  = True
	caps  = ('IDLE',)

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc_val, exc_tb):
		if not self.result and self.imap._sock:
			self.imap._sock.writeline('DONE')
			_debug2('Connection is done idling')
			self.wait()

	def __iter__(self):
		queue = self.queue
		while queue:
			yield queue.popleft()
		while not self.result and self.imap.poll():  # Do not block
			while queue:
				yield queue.popleft()

	def _is_data(self, rsp):
		return True  # Claim everything while the command is active

class ReferralCmds(IMAP4Command):  # [RFC-2193]
	state = _state
	caps  = ('MAILBOX-REFERRALS',)
	names = ('RLIST', 'RLSUB')

	def _is_data(self, rsp):
		return rsp.dtype == self.name[1:]

class NAMESPACE(IMAP4Command):  # [RFC-2342]
	state = _state
	caps  = ('NAMESPACE',)

class AclCmds(IMAP4Command):  # [RFC-4314]
	state = _state
	caps  = ('ACL',)
	names = ('SETACL', 'DELETEACL', 'GETACL', 'LISTRIGHTS', 'MYRIGHTS')
	dtype = ('ACL',)

class MetadataCmds(IMAP4Command):  # [RFC-5464]
	state = _state
	names = ('GETMETADATA', 'SETMETADATA')
	dtype = ('METADATA',)

	def _check_caps(self, imap, name, args):
		if 'METADATA' in imap.caps:
			return True
		if 'METADATA-SERVER' in imap.caps:
			return args[0] == '""'
		return False

class XLIST(IMAP4Command):  # Non-standard
	state = _state
	caps  = ('XLIST',)

# Commands valid ONLY in auth state
_state = ('auth',)

class ENABLE(IMAP4Command):  # [RFC-5161]
	state = _state
	caps  = ('ENABLE',)
	dtype = ('ENABLED',)

class PROXYAUTH(IMAP4Command):  # Non-standard
	state = _state

#
# 6.4. Client Commands - Selected State
#

_state = ('selected',)

class MessageCmds(IMAP4Command):
	state = _state
	names = ('CHECK', 'EXPUNGE', 'UID EXPUNGE', 'SEARCH', 'UID SEARCH', 'COPY',
	         'UID COPY')

	def _check_caps(self, imap, name, args):
		return name != 'UID EXPUNGE' or 'UIDPLUS' in imap.caps

class CloseCmds(IMAP4Command):
	state = _state
	excl  = True
	names = ('CLOSE', 'UNSELECT')

	def _check_caps(self, imap, name, args):
		return name != 'UNSELECT' or name in imap.caps

	def _done(self, rsp):
		if rsp.status == 'OK':
			self.imap.state = 'auth'

class FetchCmds(IMAP4Command):
	__slots__ = ('seqset',)

	state = _state
	names = ('FETCH', 'UID FETCH', 'STORE', 'UID STORE')

	def __init__(self, imap, tag, name, args):
		self.seqset = None  # Must be set externally (IMAP4SeqSet instance)

	def _is_data(self, rsp):
		if rsp.dtype == 'FETCH':
			if not self.seqset:
				return True  # Claim all responses if seqset is not set
			if not self.uid:
				return rsp[0] in self.seqset  # Match by sequence numbers
			kv = rsp[-1]
			return kv[kv.index('UID') + 1] in self.seqset  # Match by UIDs
		return False

class SortCmds(IMAP4Command):  # [RFC-5256]
	state = _state
	names = ('SORT', 'THREAD')

	def _check_caps(self, imap, name, args):
		if name == 'SORT':
			return 'SORT' in imap.caps
		return 'THREAD=' + args[0].upper() in imap.caps

#
###  Response parser  ##########################################################
#

# Response sequence number generator (shared by all IMAP4 connections)
_seq = lambda ctr=itertools.count(1): next(ctr)

# Status response format (excluding tag)
_status = re.compile(r'''
	(OK|NO|BAD|BYE|PREAUTH)  # Status condition
	(?:\ \[ ([^\]]+) \])?    # Optional response code
	(?:\ (.+))?              # Text (required by [RFC-3501], but optional here)
	$
''', re.ASCII | re.IGNORECASE | re.VERBOSE)

# Data and response code tokenizer
_token = re.compile(r'''
	"((?:[^\\"]|\\\\|\\")*)" |  # Quoted string
	~?{(\d+)} |                 # Literal reference (~ prefix means literal8)
	(?:                         # NIL or some atom variation
		[^[ ()] |               # Relaxed atom pattern
		\[ [^\]]* \]            # e.g. BODY[<everything in here>]
	)+
''', re.ASCII | re.IGNORECASE | re.VERBOSE)

# Base64 format for server authentication challenges
_base64 = re.compile(r'[A-Za-z0-9+/]*={0,2}$')

class IMAP4Response(list):
	"""Server response parser.

	The possible response types are: data (untagged), status (untagged),
	continue (continuation request), and done (tagged).

	All data items, including the optional status response codes ('data' in
	'* OK [data] text...'), are decoded into the parent list object. The first
	non-numeric data item is also stored in 'dtype' attribute to help identify
	the command that this data belongs to.

	The text of a status response, and the text or decoded base64 bytes object
	of a continuation request, are stored in the 'info' attribute.
	"""

	__slots__ = ('seq', 'text', 'data', 'type', 'tag', 'status', 'info',
	             'dtype')

	def __init__(self, text, data=None):
		list.__init__(self)

		self.seq    = _seq()  # Response sequence number
		self.text   = text    # Raw text returned by _readline
		self.data   = data    # Raw data returned by _readline
		self.type   = None    # Response type (status, data, continue, or done)
		self.tag    = None    # Response tag (*, +, or command tag)
		self.status = None    # Status condition (OK, NO, BAD, BYE, or PREAUTH)
		self.info   = None    # Status text or decoded base64 bytes object
		self.dtype  = None    # First non-numeric data item (upper case string)

		try:
			tag, s = text.split(' ', 1)
			self.tag = tag
			if tag == '*':
				if self._parse_status(s):
					self.type = 'status'
				else:
					self._parse_data(s)
					self.type = 'data'
			elif tag == '+':
				self._parse_continue(s)
				self.type = 'continue'
			elif self._parse_status(s):
				self.type = 'done'
			else:
				raise ParseError('unknown response type', tag)
			if len(self):
				self.dtype = self[0 if isinstance(self[0], str) else 1].upper()
		except Exception as exc:
			raise ParseError('failed to parse response', ascii(text)) from exc
		finally:
			if _debug_level >= 5:
				_debug5(self)

	def __str__(self):
		attrs = ', '.join(map('{0[0]}={0[1]!a}'.format, (
			('seq',    self.seq),
			('type',   self.type),
			('tag',    self.tag),
			('status', self.status),
			('info',   self.info),
			('dtype',  self.dtype),
			('data',   tuple(self))
		)))
		return '{}({})'.format(self.__class__.__name__, attrs)

	def __repr__(self):
		return '{}({!a})'.format(self.__class__.__name__, self.text)

	def __bool__(self):
		"""Override list truth testing.

		Use dtype attribute to determine if the response contains any data.
		"""
		return True

	def _parse_status(self, s):
		"""Try to parse a tagged or untagged status response."""
		match = _status.match(s)
		if match:
			status, data, self.info = match.groups()
			self.status = status.upper()
			if data:
				self._parse_data(data)
			return True
		return False  # Untagged data

	def _parse_continue(self, s):
		"""Parse continuation request."""
		if ' ' not in s and _base64.match(s):
			try:
				s = b64decode(s.encode('ascii'))
			except Exception:
				pass
		self.info = s

	def _parse_data(self, s):
		"""Parse data response or status response code."""
		if not s:
			raise ParseError('incomplete response')

		stack = deque()  # Stack of lists for keeping track of parentheses
		dst   = self     # Current list
		pos   = 0        # Current position
		stop  = len(s)   # Final position

		while pos < stop:
			c = s[pos]
			if c == ' ':
				pos += 1
			elif c == '(':
				stack.append(dst)
				dst.append([])
				dst = dst[-1]
				pos += 1
			elif c == ')':
				dst = stack.pop()
				pos += 1
			else:
				tok = _token.match(s, pos)
				if not tok:
					raise ParseError('invalid token', s[pos:])
				pos = tok.end()
				if tok.lastindex == 1:
					qstr = tok.group(1)
					dst.append(qstr.replace('\\"', '"').replace('\\\\', '\\'))
				elif tok.lastindex == 2:
					dst.append(self.data[int(tok.group(2))])
				else:
					atom = tok.group()
					if atom.isdigit():
						atom = int(atom)
					elif atom.upper() == 'NIL':
						atom = None
					dst.append(atom)
		if stack:
			raise ParseError('unterminated parenthesized list')

#
###  Socket interface  #########################################################
#

if ssl:
	_blocking_errnos = set(socket._blocking_errnos)
	_blocking_errnos.add(ssl.SSL_ERROR_WANT_READ)
else:
	_blocking_errnos = socket._blocking_errnos

class IMAP4Socket:

	def __init__(self, addr, timeout, ssl_ctx=None, bufsize=65536):
		"""Connect to the server."""
		_debug1('Opening socket [addr={!a}, timeout={!a}, ssl={!a}]', addr,
		        timeout, bool(ssl_ctx))

		if timeout == 0.0:
			raise ValueError('non-blocking socket mode is not supported')

		self.addr     = addr
		self._timeout = timeout
		self._bufsize = bufsize
		self._linebuf = []
		self._sock    = socket.create_connection(addr, timeout)
		try:
			self._sock_io = SocketIO(self._sock)
			self._istream = io.BufferedReader(self._sock_io, bufsize)
			self._ostream = io.BufferedWriter(self._sock_io, bufsize)
			if ssl_ctx:
				_debug1('Performing SSL negotiation...')
				self.starttls(ssl_ctx)
		except Exception:
			self._shutdown(self._sock)
			raise

	def readline(self):
		"""Read a complete line of ASCII text up to the first CRLF sequence."""
		# Check if a complete line is already buffered (from a previous peek)
		buf = self._linebuf
		if isinstance(buf, str):
			self._linebuf = []
			_debug4('S: {}', buf)
			return buf

		# Read from the input stream (the socket is in blocking or timeout mode)
		text = self._istream.readline(self._bufsize)
		if text.endswith(b'\r\n'):
			text = text[:-2].decode('ascii')
			if buf:
				self._linebuf = []
				buf.append(text)
				text = ''.join(buf)
			_debug4('S: {}', text)
			return text

		# EOF, buffer corruption, or an actual line that exceeds bufsize limit
		raise ProtocolError('missing CRLF sequence (may be EOF)', ascii(text))

	def peekline(self):
		"""Try to read a complete line of text up to the first CRLF sequence.

		This function never blocks and returns None if a complete line of text
		is not available. Otherwise, the line is kept in an internal buffer to
		be returned again for the next peekline or readline call.
		"""
		# Check if a complete line is already buffered (from a previous peek)
		buf = self._linebuf
		if isinstance(buf, str):
			return buf

		# Try to read from the input stream in non-blocking mode
		self._sock.setblocking(False)
		try:
			text = self._istream.readline(self._bufsize)
		finally:
			if self._sock.fileno() >= 0:
				self._sock.settimeout(self._timeout)

		# Append new data to the line buffer
		if text:
			if text.endswith(b'\r\n'):
				text = text[:-2].decode('ascii')
				if buf:
					buf.append(text)
					text = ''.join(buf)
				self._linebuf = text
				return text
			if text[-1] == b'\n':
				raise ProtocolError('missing CR character', ascii(text))
			buf.append(text.decode('ascii'))
		return None

	def read(self, nbytes):
		"""Read a literal string."""
		data = self._istream.read(nbytes)
		n = len(data)  # None not expected; socket is blocking (or timeout)
		if n != nbytes:
			# BufferedReader does not return partial reads, except on EOF
			raise ProtocolError('EOF while reading literal')
		_debug4('S: <literal {} bytes>', n)
		return data

	def writeline(self, text, flush=True):
		"""Write a single ASCII line."""
		_debug4('C: {}', text)
		self._ostream.write(text.encode('ascii') + b'\r\n')
		if flush:
			self._ostream.flush()

	def write(self, data):
		"""Write a literal string."""
		n = len(data)
		_debug4('C: <literal {} bytes>', n)
		# This is always followed by writeline, so no need to flush
		if self._ostream.write(data) != n:
			raise ProtocolError('EOF while writing literal')

	def block(self, timeout=None):
		"""Block execution until some new data is available from the socket.

		This method exists because the socket timeout mechanism cannot be reused
		once triggered. Any data that was already buffered is lost, so the
		socket must be closed. See issue #7322.

		This method may be used to safely block execution until some new data is
		received or the timeout expires. The peekline() method may then be used
		to check if a complete response line is available in the buffer.
		"""
		return True if select((self._sock,), (), (), timeout)[0] else False

	def flush(self):
		"""Flush outgoing stream buffer."""
		self._ostream.flush()

	def starttls(self, ssl_ctx):
		"""Enable SSL or TLS encryption."""
		self._sock_io._sock = self._sock = ssl_ctx.wrap_socket(self._sock)
		_debug1('SSL/TLS enabled {}', self._sock.cipher())

		if ssl_ctx.verify_mode == ssl.CERT_REQUIRED:
			host = self.addr[0]
			cert = self._sock.getpeercert()
			if _debug_level >= 2:
				from pprint import pformat
				_debug2('Peer certificate:\n{}', pformat(cert))
				_debug2('Matching certificate hostname: {}', host)
			ssl.match_hostname(cert, host)

	def compress_deflate(self, level):
		"""Enabled DEFLATE compression."""
		level = max(1, min(level, 9))
		self._sock_io.enable_deflate(level)
		_debug1('DEFLATE compression enabled [level={}]', level)

	def info(self, reset=False):
		"""Get the number of bytes received and transmitted."""
		io = self._sock_io
		rt = (io.rx_bytes, io.tx_bytes)
		if reset:
			io.rx_bytes = io.tx_bytes = 0
		return rt

	def close(self):
		"""Close socket."""
		if not self._sock:
			return
		try:
			self._istream.detach()
			self._ostream.detach()
			_debug1('Closing socket [rx_bytes={}, tx_bytes={}]', *self.info())
			self._shutdown(self._sock)
		finally:
			self._sock    = None
			self._istream = None
			self._ostream = None
			self._sock_io.close()  # Keep SocketIO reference for info() and eof

	@property
	def encrypted(self):
		"""Link encryption status."""
		return ssl and isinstance(self._sock, ssl.SSLSocket)

	@property
	def compressed(self):
		"""Link compression status."""
		return self._sock_io.deflate is not None

	@property
	def timeout(self):
		"""Socket timeout setting."""
		return self._timeout

	@property
	def eof(self):
		"""End-of-file status."""
		return self._sock_io.eof

	@timeout.setter
	def timeout(self, value):
		if value == 0.0:
			raise ValueError('non-blocking socket mode is not supported')
		self._sock.settimeout(value)
		self._timeout = value

	def _shutdown(self, sock):
		"""Shutdown and close the socket."""
		if sock.fileno() < 0:
			return
		try:
			sock.shutdown(socket.SHUT_RDWR)
		except socket.error as exc:
			if exc.errno != errno.ENOTCONN:
				raise
		finally:
			sock.close()

class SocketIO(io.RawIOBase):
	"""Custom SocketIO class that supports compression.

	Unlike socket.SocketIO, this class doesn't support any mode other than 'rwb'
	and never calls close() on the underlying socket. That task is handled by
	IMAP4Socket. This is simply an interface between one of the BufferedIOBase
	classes and the socket, with optional support for data compression using
	zlib's DEFLATE algorithm.
	"""

	def __init__(self, sock):
		super().__init__()
		self._sock    = sock
		self.eof      = False
		self.inflate  = None
		self.deflate  = None
		self.rx_bytes = 0
		self.tx_bytes = 0

	def enable_deflate(self, level, wbits=-zlib.MAX_WBITS):
		# Documentation for compressobj is incomplete, see zlibmodule.c source
		deflate = zlib.compressobj(level, zlib.DEFLATED, wbits)
		self.inflate = zlib.decompressobj(wbits)
		self.deflate = deflate

	def readinto(self, b):
		# If compression is enabled, consume existing data first
		lim = len(b)
		inf = self.inflate
		if inf and inf.unconsumed_tail:
			d = inf.decompress(inf.unconsumed_tail, lim)
			# Decompress may return nothing, even if there is a tail
			if d:
				n = len(d)
				b[:n] = d
				return n

		# Read data from the socket, which may be in non-blocking mode
		while True:
			try:
				n = self._sock.recv_into(b)
				if n:
					self.rx_bytes += n
					if inf:
						t = inf.unconsumed_tail
						d = inf.decompress(t + b[:n] if t else b[:n], lim)
						if not d:
							continue  # Need more data to decompress
						n = len(d)
						b[:n] = d
				else:
					self.eof = True
				return n
			except socket.error as exc:
				if exc.errno == socket.EINTR:
					continue
				if exc.errno in _blocking_errnos:
					return None
				raise

	def write(self, b):
		# Socket must NOT be in non-blocking mode; EINTR is handled by sendall()
		n = len(b)
		if self.deflate:
			d = self.deflate.compress(b)
			if d:
				self._sock.sendall(d)
				self.tx_bytes += len(d)
			d = self.deflate.flush(zlib.Z_SYNC_FLUSH)  # Must send everything
			if d:
				self._sock.sendall(d)
				self.tx_bytes += len(d)
		else:
			self._sock.sendall(b)
			self.tx_bytes += n
		return n

	def close(self):
		self._sock   = None
		self.eof     = True
		self.inflate = None
		self.deflate = None
		super().close()

	readable = lambda self: True
	writable = lambda self: True
	fileno   = lambda self: self._sock.fileno() if self._sock else -1
	name     = property(fileno)
	mode     = 'rwb'

#
###  Sequence set container  ###################################################
#

class IMAP4SeqSet(set):
	"""Class for storing message sequence numbers (SNs) or UIDs.

	This class may only be used for storing a determinate set of SNs or UIDs
	(i.e. one that does not contain '*' or '$').
	"""

	def __init__(self, seq=()):
		"""Create new set from a string or a sequence of ints."""
		if seq and isinstance(seq, str):
			if '*' in seq:
				raise ValueError('highest SN or UID not known')
			if seq == '$':
				raise ValueError('last search result not known')  # [RFC-5182]
			super().__init__()
			add    = self.add
			update = self.update
			for v in seq.split(','):
				if ':' in v:
					a, b = map(int, v.split(':', 1))
					update(range(a, b + 1) if a <= b else range(b, a + 1))
				else:
					add(int(v))
		else:
			super().__init__(seq)

	def __str__(self):
		"""Get a comma-separated list of SNs or UIDs contained in this set.

		The resulting list will be sorted. Three or more contiguous SNs or UIDs
		will be combined into FIRST:LAST ranges.
		"""
		if not self:
			return ''
		parts = []
		seq   = iter(sorted(self))
		first = prev = next(seq)
		for v in itertools.chain(seq, (None,)):
			if v != prev + 1:
				if prev == first:
					parts.append(str(first))
				else:
					sep = ',' if prev == first + 1 else ':'
					parts.append(str(first) + sep + str(prev))
				first = v
			prev = v
		return ','.join(parts)

#
###  Test server  ##############################################################
#

class IMAP4Test(threading.Thread):
	"""A dummy IMAP4 server that follows a pre-defined response script."""

	def __init__(self, addr=('127.0.0.1', 0), script=None, ssl_ctx=None):
		self.addr = addr  # Server address
		self.sock = None  # Listening socket
		self.conn = None  # Client connection
		self.file = None  # Connection file interface
		self.tag  = None  # Tag prefix used by the client

		if script is not None:
			self.script = script
		self.ssl_ctx = ssl_ctx
		super().__init__()

	def __enter__(self):
		"""Create a listening socket and start the server thread."""
		self.sock = socket.socket()
		try:
			self.sock.bind(self.addr)
			self.sock.listen(1)
			self.addr = self.sock.getsockname()
			self.start()
		except Exception:
			self._close()
			raise
		return self

	def __exit__(self, exc_type, exc_val, exc_tb):
		"""Terminate server thread and close all sockets."""
		self._close()
		self.join(10)
		if self.is_alive():
			raise RuntimeError('failed to terminate server thread')

	def __call__(self, *args):
		"""Send response lines and literals."""
		for arg in args:
			if isinstance(arg, str):
				arg = arg.encode('ascii') + b'\r\n'
			self.conn.sendall(arg)

	def __next__(self):
		"""Read the next client command or response."""
		text, data = _readline(self)
		if self.tag is None:
			tag, text = text.split(None, 1)
			self.tag  = re.match('[A-Z]+', tag).group(0)
		elif text.startswith(self.tag):
			tag, text = text.split(None, 1)
		else:
			tag = None
		return (tag, text, data)

	def greeting(self, status='OK', name=None, caps=None, resp_code=False):
		"""Send server greeting."""
		if name is None:
			name = self.script.__name__
			if name == 'script':
				name = self.__class__.__name__
		if caps and resp_code:
			status += ' [CAPABILITY {}]'.format(' '.join(caps))
			caps = None
		self('* {} {} is ready...'.format(status, name))
		if caps is not None:
			self.caps(*caps)

	def caps(self, *caps, as_data=False):
		"""Send a capability response."""
		if not as_data:
			tag = next(self)[0]
		self('* CAPABILITY ' + ' '.join(caps))
		if not as_data:
			self.done(tag)

	def starttls(self, ssl_ctx):
		"""Enable SSL or TLS."""
		if self.file:
			self.file.close()
		self.conn = ssl_ctx.wrap_socket(self.conn, server_side=True)
		self.file = self.conn.makefile('rb')

	def script(self):
		"""Server response script."""
		self('* BYE Nothing to do')

	def done(self, tag, result='OK'):
		"""Send command completion response."""
		self(tag + ' ' + result)

	def logout(self):
		"""Wait for a logout command from the client."""
		tag = next(self)[0]
		self('* BYE')
		self.done(tag)

	def run(self):
		"""Thread entry point."""
		self.conn = self.sock.accept()[0]
		if self.ssl_ctx:
			self.starttls(self.ssl_ctx)
		else:
			self.file = self.conn.makefile('rb')
		self.conn.settimeout(10)
		if getattr(self.script, '__self__', None) is self:
			self.script()
		else:
			self.script(self)

	def _readline(self):
		line = self.file.readline()
		if not line.endswith(b'\r\n'):
			raise RuntimeError('EOF')
		return line[:-2].decode('ascii')

	def _read(self, n):
		data = self.file.read(n)
		if len(data) != n:
			raise RuntimeError('EOF')
		return data

	# _readline interface
	readline, read = _readline, _read

	def _close(self):
		if self.file:
			self.file.close()
		for sock in (self.conn, self.sock):
			if not sock:
				continue
			try:
				if sock.fileno() >= 0:
					sock.shutdown(socket.SHUT_RDWR)
			except Exception:
				pass
			sock.close()
