
#
# Written by Maxim Khitrov (July 2011)
#

import os
import sys

#
###  Runtime environment  ######################################################
#

# Location of the executable
RUN_DIR = os.path.realpath(os.path.dirname(sys.argv[0]))

# Flag set to True when the script is running via cx_Freeze
FROZEN = getattr(sys, 'frozen', False)

# Package directory
PKG_DIR = RUN_DIR if FROZEN else os.path.dirname(__file__)

#
###  IMAP4 connection  #########################################################
#

# File containing SSL CA certificates
CA_FILE = os.path.join(PKG_DIR, 'misc', 'ca.pem')

# Two-legged OAuth authentication parameters (only for Google Apps domains)
OAUTH_KEY    = None
OAUTH_SECRET = None
OAUTH_URL    = 'https://mail.google.com/mail/b/{account}/imap/'

# Do not send program name, version, and contact info in client ID
PROTECT_ID = False

# XLIST reference for special Gmail mailboxes
GMAIL_REF = '[Gmail]/'

# Gmail special labels
GMAIL_SPECIAL = ('\\Inbox', '\\Important', '\\Starred', '\\Draft', '\\Sent')

#
###  Database parameters  ######################################################
#

# Root directory (used when database path on the command-line is relative)
ROOT_DIR = os.getcwd()

# File and directory modes
FILE_MODE = 0o600
DIR_MODE  = 0o700

# Main database file name and user version
DB_NAME = 'gmdb.sqlite'
DB_VER  = 1000

# Index database file name and user version
DB_IDX_NAME = 'index.sqlite'
DB_IDX_VER  = 1000

# PRAGMA synchronous flag ('off', 'normal', 'full')
DB_SYNC = 'off'

# Path to the SQLite FTS extension (if compiled as a separate shared library)
DB_FTS_EXT = None

# Supported FTS versions in the order of preference
DB_FTS_VER = ('fts4', 'fts3')

# FTS tokenizer name and parameters
DB_FTS_TOK = 'simple'

# Delay insert/update operations on the 'msg' table during a backup
DB_DELAYED_OPS = False

#
###  Backup operation  #########################################################
#

# Number of messages to process at a time (checkpoint granularity)
BATCH_SIZE = 1000

# Maximum size (in bytes) of the sequence set argument to the FETCH UIDs command
# Note: This affects checkpoint granularity. A 16k limit doesn't follow
#       [RFC-2683], but is ok for Gmail and allows a BATCH_SIZE of 1000 to cover
#       2139000 messages without adjustments.
FETCH_LIMIT = 16000

# Maximum size of the downloaded message buffer (0 = disable)
DL_BUFFER_LIMIT = 26214400

#
###  User configuration  #######################################################
#

# User configuration file path
CONF_PATH = ['gmdb.conf']

if os.name == 'nt':
	CONF_PATH.append(os.path.join(os.getenv('USERPROFILE', ''), 'gmdb.conf'))
else:
	CONF_PATH.extend((
		os.path.join(os.getenv('HOME'), '.gmdb'),
		os.path.join(sys.prefix, 'etc', 'gmdb.conf'),
		'/etc/gmdb.conf'
	))

del os, sys
