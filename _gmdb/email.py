
#
# Written by Maxim Khitrov (July 2011)
#

from email.parser import BytesParser
from email.header import decode_header, make_header
from email.utils import getaddresses, parsedate_tz, mktime_tz

import codecs

parser = BytesParser()

def parse(fd):
	msg  = parser.parse(fd)
	date = parsedate_tz(msg['date']) if 'date' in msg else None
	to   = []

	for name in ('to', 'cc', 'bcc', 'resent-to', 'resent-cc', 'resent-bcc'):
		if name in msg:
			to.extend(msg.get_all(name))

	for part in msg.walk():
		if not part.is_multipart() and part.get_content_type() == 'text/plain':
			payload = part.get_payload(decode=True)
			text    = payload.decode(_charset(part), 'replace')
			break
	else:
		text = ''

	return {
		'date':    mktime_tz(date) if date else None,
		'from':    _addrs(msg.get_all('from', ())),
		'to':      _addrs(to),
		'subject': _hdr_str(msg['subject'] or ''),
		'body':    text
	}

def _charset(msg):
	charset = msg.get_content_charset('US-ASCII')
	if charset.startswith('"'):
		charset = charset.split('"', 2)[1]  # Charset wasn't properly unquoted
	try:
		codecs.lookup(charset)
		return charset
	except LookupError:
		return 'US-ASCII'

def _addrs(hdrs):
	_hdrs = tuple(hdrs)
	hdrs  = []
	parts = []
	for hdr in _hdrs:
		if isinstance(hdr, str):
			hdrs.append(hdr)
		else:
			parts.append(str(hdr))
	for name, addr in getaddresses(hdrs):
		if name:
			parts.append(_hdr_str(name))
		parts.append(addr)
	return ' '.join(parts)

def _hdr_str(hdr):
	# hdr could be a Header instance
	return str(make_header(decode_header(hdr)) if isinstance(hdr, str) else hdr)
