# Copyright 2014 Red Hat, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import sys

import debtcollector.removals


def safe_decode(text, incoming=None, errors='strict'):
    """Decodes incoming text/bytes string using `incoming` if they're not
       already unicode.

    :param incoming: Text's current encoding
    :param errors: Errors handling policy. See here for valid
        values http://docs.python.org/2/library/codecs.html
    :returns: text or a unicode `incoming` encoded
                representation of it.
    :raises TypeError: If text is not an instance of str
    """
    if not isinstance(text, (str, bytes)):
        raise TypeError("%s can't be decoded" % type(text))

    if isinstance(text, str):
        return text

    if not incoming:
        incoming = (getattr(sys.stdin, 'encoding', None) or
                    sys.getdefaultencoding())

    try:
        return text.decode(incoming, errors)
    except UnicodeDecodeError:
        # Note(flaper87) If we get here, it means that
        # sys.stdin.encoding / sys.getdefaultencoding
        # didn't return a suitable encoding to decode
        # text. This happens mostly when global LANG
        # var is not set correctly and there's no
        # default encoding. In this case, most likely
        # python will use ASCII or ANSI encoders as
        # default encodings but they won't be capable
        # of decoding non-ASCII characters.
        #
        # Also, UTF-8 is being used since it's an ASCII
        # extension.
        return text.decode('utf-8', errors)


def safe_encode(text, incoming=None,
                encoding='utf-8', errors='strict'):
    """Encodes incoming text/bytes string using `encoding`.

    If incoming is not specified, text is expected to be encoded with
    current python's default encoding. (`sys.getdefaultencoding`)

    :param incoming: Text's current encoding
    :param encoding: Expected encoding for text (Default UTF-8)
    :param errors: Errors handling policy. See here for valid
        values http://docs.python.org/2/library/codecs.html
    :returns: text or a bytestring `encoding` encoded
                representation of it.
    :raises TypeError: If text is not an instance of str

    See also to_utf8() function which is simpler and don't depend on
    the locale encoding.
    """
    if not isinstance(text, (str, bytes)):
        raise TypeError("%s can't be encoded" % type(text))

    if not incoming:
        incoming = (getattr(sys.stdin, 'encoding', None) or
                    sys.getdefaultencoding())

    # Avoid case issues in comparisons
    if hasattr(incoming, 'lower'):
        incoming = incoming.lower()
    if hasattr(encoding, 'lower'):
        encoding = encoding.lower()

    if isinstance(text, str):
        return text.encode(encoding, errors)
    elif text and encoding != incoming:
        # Decode text before encoding it with `encoding`
        text = safe_decode(text, incoming, errors)
        return text.encode(encoding, errors)
    else:
        return text


def to_utf8(text):
    """Encode Unicode to UTF-8, return bytes unchanged.

    Raise TypeError if text is not a bytes string or a Unicode string.

    .. versionadded:: 3.5
    """
    if isinstance(text, bytes):
        return text
    elif isinstance(text, str):
        return text.encode('utf-8')
    else:
        raise TypeError("bytes or Unicode expected, got %s"
                        % type(text).__name__)


@debtcollector.removals.remove(message='Use str(exc) instead',
                               category=DeprecationWarning)
def exception_to_unicode(exc):
    """Get the message of an exception as a Unicode string.

    On Python 3, the exception message is always a Unicode string.

    .. versionadded:: 1.6
    """
    return str(exc)
