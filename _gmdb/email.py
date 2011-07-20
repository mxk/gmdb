
#
# Written by Maxim Khitrov (July 2011)
#

from email.parser import BytesParser
from email.header import decode_header, make_header
from email.utils import getaddresses, parsedate_tz, mktime_tz

parser = BytesParser()
dec    = lambda hdr: str(make_header(decode_header(hdr)))
addrs  = lambda hdr: ' '.join(dec(n) + ' ' + a for n, a in getaddresses(hdr))

def parse(fd):
	msg  = parser.parse(fd)
	date = parsedate_tz(msg['date']) if 'date' in msg else None
	to   = []

	for name in ('to', 'cc', 'bcc', 'resent-to', 'resent-cc', 'resent-bcc'):
		if name in msg:
			to.extend(msg.get_all(name))

	for part in msg.walk():
		if not part.is_multipart() and part.get_content_type() == 'text/plain':
			charset = part.get_content_charset('US-ASCII')
			payload = part.get_payload(decode=True)
			text    = payload.decode(charset, 'replace')
			break
	else:
		text = ''

	return {
		'date':    mktime_tz(date) if date else None,
		'from':    addrs(msg.get_all('from', ())),
		'to':      addrs(to),
		'subject': dec(msg['subject'] or ''),
		'body':    text
	}
