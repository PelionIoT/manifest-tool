# -*- coding: utf-8 -*-
# ----------------------------------------------------------------------------
# Copyright 2017 ARM Limited or its affiliates
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ----------------------------------------------------------------------------
from __future__ import division
import sys, time, collections, hashlib, logging
from manifesttool import __version__ as uc_version
from manifesttool import codec

from pyasn1.codec.der import encoder as der_encoder
from pyasn1.error import PyAsn1Error

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from future.moves.urllib.request import urlopen, Request
from future.moves.urllib.parse import urlparse, urlencode
from future.moves.urllib.error import HTTPError, URLError

from builtins import bytes

LOG = logging.getLogger(__name__)

def fatal(message, *args):
    """Log a fatal error and exit with an unsuccessful code."""
    LOG.critical(message, *args)
    sys.exit(1)

def read_file(fname):
    with open(fname, 'rb') as f:
        return f.read()

def calculate_hash(options, m):
    md = hashes.Hash(hashes.SHA256(), backend=default_backend())
    md.update(m)
    return md.finalize()

def sha_hash(content):
    sha = hashlib.sha256()
    sha.update(content)
    return sha.digest()

def getDevicePSK_HKDF(mode, masterKey, vendorId, classId, keyUsage):
    # Construct the device PSK
    # Device UUID is the IKM.
    hashAlg = {
        'aes-128-ctr-ecc-secp256r1-sha256' : hashes.SHA256,
        'none-ecc-secp256r1-sha256': hashes.SHA256,
        'none-none-sha256': hashes.SHA256,
        'none-psk-aes-128-ccm-sha256': hashes.SHA256,
        'psk-aes-128-ccm-sha256': hashes.SHA256
    }.get(mode)

    hkdf = HKDF(
        algorithm = hashAlg(),
        length = 128//8,
        # The master key is the salt
        salt = masterKey,
        # Device Vendor ID + Device Class ID is the info
        info = keyUsage + vendorId + classId,
        backend = default_backend()
    )
    return hkdf

def download_file(url):
    # Create request structure
    LOG.debug('Trying to download: {}'.format(url))
    try:
        req = Request(url)
    except ValueError as e:
        fatal('Client error. Could not download %r as the URL is invalid. Error: %r', url, str(e))
    req.add_header('User-Agent', 'ARM Update Client/%s)' % uc_version)

    # Read and return
    try:
        r = urlopen(req)
        content = r.read()
        r.close()
        return content
    except URLError as e:
        fatal('Could not download %r. Client error: %r', url, str(e))
    except HTTPError as e:
        fatal('Could not download %r. Server error: %r', url, str(e))

def todict(obj):
  """
  Recursively convert a Python object graph to sequences (lists)
  and mappings (dicts) of primitives (bool, int, float, string, ...)
  http://stackoverflow.com/a/22679824/503866
  """
  if sys.version_info.major == 3 and isinstance(obj, (str,bytes)):
    return obj
  elif sys.version_info.major == 2 and isinstance(obj, (str,bytes,unicode)):
    return obj
  elif isinstance(obj, dict):
    return dict((key, todict(val)) for key, val in obj.items() if val is not None)
  elif isinstance(obj, collections.Iterable):
    return [todict(val) for val in obj]
  elif hasattr(obj, '__dict__'):
    return todict(vars(obj))
  elif hasattr(obj, '__slots__'):
    return todict(dict((name, getattr(obj, name)) for name in getattr(obj, '__slots__')))
  return obj

def override_kwargs(obj, kwargs):
    for key, value in kwargs.items():
        if not value:
            continue
        if hasattr(obj, key):
            setattr(obj, key, value)

def encode(data, options, schema):
    encoder = {
        'der': der_encoder,
    }[options.encoding]

    try:
        asn = codec.obj2asn(data, schema)
        output = encoder.encode(asn)
        return output
    except PyAsn1Error as err:
        import traceback
        # exc_type, exc_value, exc_traceback = sys.exc_info()
        # traceback.print_stack()
        # traceback.print_tb(exc_traceback)
        LOG.critical('PyAsn1Error. This is propbably a bug. Could not encode '
                    'generated manifest.\nEnsure all fields are properly defined and '
                    'provided. Also check, in the case of the manifest changing, that '
                    'the generated "manifest_definition.py" file is up to date. The file can '
                    'be re-generated with the asn1py.py tool. Error message: "{0}"'.format(err))
        return None

def skipAhead(code):
    rc = 0
    if code == 0x81:
        rc = 1
    if code == 0x82:
        rc = 2
    if code == 0x83:
        rc = 3
    if code == 0x83:
        rc = 4
    return rc

def detect_version(input_file):
    # 32 bytes is currently sufficient to detect the manifest type.
    headerData = bytes(input_file.read(32))
    input_file.seek(0)
    # In both cases, the manifest starts with a DER SEQUENCE tag.
    if headerData[0] != 0x30:
        LOG.critical("input file is not a manifest.")
        return None
    # skip past the length
    pos = 2 + skipAhead(headerData[1])

    version = None
    # For version 1, the first object in the SEQUENCE should be another SEQUENCE
    if headerData[pos] == 0x30:
        version = '1'
    # For version 2+, a CMS wrapper is used, so the tag should be an OID tag
    if headerData[pos] == 0x06:
        version = '2'

    return version
