
#
# Written by Maxim Khitrov (July 2011)
#

from base64 import b64encode
from hashlib import sha1
from os import urandom
from time import time
from urllib.parse import quote

import hmac
import logging

__all__ = ['OAuth']

log = logging.getLogger('gmdb.oauth')

def _penc(s):
	"""Percent-encode a string according to [RFC-5849] Section 3.6."""
	return quote(s, safe='~')

class OAuth:
	"""Two-legged OAuth implementation for Gmail IMAP."""

	def __init__(self, key, secret, url, method='GET'):
		"""Set authentication parameters."""
		if not (key and secret and url and method):
			raise ValueError('invalid oauth parameters')
		self.key    = key
		self.secret = secret
		self.url    = url
		self.method = method

	def __call__(self, account):
		"""Create a request string for OAuth authentication."""
		url  = self.url.format(account=account)
		args = {
			'oauth_consumer_key':     _penc(self.key),
			'oauth_nonce':            sha1(urandom(64)).hexdigest(),
			'oauth_signature_method': 'HMAC-SHA1',
			'oauth_timestamp':        str(int(time())),
			'oauth_version':          '1.0',
			'xoauth_requestor_id':    _penc(account)
		}

		# Sign the request and move 'xoauth_requestor_id' into the url
		args['oauth_signature'] = _penc(self._sig(url, args))
		url += '?xoauth_requestor_id=' + args.pop('xoauth_requestor_id')

		# Create the final request string
		args = ','.join(map('{0[0]}="{0[1]}"'.format, sorted(args.items())))
		req  = '{} {} {}'.format(self.method, url, args)

		log.debug2('OAuth request: {}', req)
		return req.encode()

	def _sig(self, url, args, token_secret=''):
		"""Create a base64-encoded oauth_signature parameter."""
		url  = _penc(url)
		args = '&'.join(map('{0[0]}={0[1]}'.format, sorted(args.items())))
		key  = '&'.join((self.secret, token_secret)).encode()
		base = '&'.join((self.method, url, _penc(args))).encode()
		sig  = hmac.new(key, base, sha1).digest()
		return b64encode(sig).decode('ascii')
