# Copyright 2011 OpenStack Foundation.
# Copyright 2012, Red Hat, Inc.
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

"""
Exception related utilities.
"""

import logging
import os
import sys
import time
import traceback

import six

from oslo_utils._i18n import _LE
from oslo_utils import reflection


class CausedByException(Exception):
    """Base class for exceptions which have associated causes.

    NOTE(harlowja): in later versions of python we can likely remove the need
    to have a ``cause`` here as PY3+ have implemented :pep:`3134` which
    handles chaining in a much more elegant manner.

    :param message: the exception message, typically some string that is
                    useful for consumers to view when debugging or analyzing
                    failures.
    :param cause: the cause of the exception being raised, when provided this
                  should itself be an exception instance, this is useful for
                  creating a chain of exceptions for versions of python where
                  this is not yet implemented/supported natively.
    """
    def __init__(self, message, cause=None):
        super(CausedByException, self).__init__(message)
        self.cause = cause

    def __bytes__(self):
        return self.pformat().encode("utf8")

    def __str__(self):
        return self.pformat()

    def _get_message(self):
        # We must *not* call into the ``__str__`` method as that will
        # reactivate the pformat method, which will end up badly (and doesn't
        # look pretty at all); so be careful...
        return self.args[0]

    def pformat(self, indent=2, indent_text=" ", show_root_class=False):
        """Pretty formats a caused exception + any connected causes."""
        if indent < 0:
            raise ValueError("Provided 'indent' must be greater than"
                             " or equal to zero instead of %s" % indent)
        buf = six.StringIO()
        if show_root_class:
            buf.write(reflection.get_class_name(self, fully_qualified=False))
            buf.write(": ")
        buf.write(self._get_message())
        active_indent = indent
        next_up = self.cause
        seen = []
        while next_up is not None and next_up not in seen:
            seen.append(next_up)
            buf.write(os.linesep)
            if isinstance(next_up, CausedByException):
                buf.write(indent_text * active_indent)
                buf.write(reflection.get_class_name(next_up,
                                                    fully_qualified=False))
                buf.write(": ")
                buf.write(next_up._get_message())
            else:
                lines = traceback.format_exception_only(type(next_up), next_up)
                for i, line in enumerate(lines):
                    buf.write(indent_text * active_indent)
                    if line.endswith("\n"):
                        # We'll add our own newlines on...
                        line = line[0:-1]
                    buf.write(line)
                    if i + 1 != len(lines):
                        buf.write(os.linesep)
            if not isinstance(next_up, CausedByException):
                # Don't go deeper into non-caused-by exceptions... as we
                # don't know if there exception 'cause' attributes are even
                # useable objects...
                break
            active_indent += indent
            next_up = getattr(next_up, 'cause', None)
        return buf.getvalue()


def raise_with_cause(exc_cls, message, *args, **kwargs):
    """Helper to raise + chain exceptions (when able) and associate a *cause*.

    NOTE(harlowja): Since in py3.x exceptions can be chained (due to
    :pep:`3134`) we should try to raise the desired exception with the given
    *cause* (or extract a *cause* from the current stack if able) so that the
    exception formats nicely in old and new versions of python. Since py2.x
    does **not** support exception chaining (or formatting) the exception
    class provided should take a ``cause`` keyword argument (which it may
    discard if it wants) to its constructor which can then be
    inspected/retained on py2.x to get *similar* information as would be
    automatically included/obtainable in py3.x.

    :param exc_cls: the exception class to raise (typically one derived
                    from :py:class:`.CausedByException` or equivalent).
    :param message: the text/str message that will be passed to
                    the exceptions constructor as its first positional
                    argument.
    :param args: any additional positional arguments to pass to the
                 exceptions constructor.
    :param kwargs: any additional keyword arguments to pass to the
                   exceptions constructor.
    """
    if 'cause' not in kwargs:
        exc_type, exc, exc_tb = sys.exc_info()
        try:
            if exc is not None:
                kwargs['cause'] = exc
        finally:
            # Leave no references around (especially with regards to
            # tracebacks and any variables that it retains internally).
            del(exc_type, exc, exc_tb)
    six.raise_from(exc_cls(message, *args, **kwargs), kwargs.get('cause'))


class save_and_reraise_exception(object):
    """Save current exception, run some code and then re-raise.

    In some cases the exception context can be cleared, resulting in None
    being attempted to be re-raised after an exception handler is run. This
    can happen when eventlet switches greenthreads or when running an
    exception handler, code raises and catches an exception. In both
    cases the exception context will be cleared.

    To work around this, we save the exception state, run handler code, and
    then re-raise the original exception. If another exception occurs, the
    saved exception is logged and the new exception is re-raised.

    In some cases the caller may not want to re-raise the exception, and
    for those circumstances this context provides a reraise flag that
    can be used to suppress the exception.  For example::

      except Exception:
          with save_and_reraise_exception() as ctxt:
              decide_if_need_reraise()
              if not should_be_reraised:
                  ctxt.reraise = False

    If another exception occurs and reraise flag is False,
    the saved exception will not be logged.

    If the caller wants to raise new exception during exception handling
    he/she sets reraise to False initially with an ability to set it back to
    True if needed::

      except Exception:
          with save_and_reraise_exception(reraise=False) as ctxt:
              [if statements to determine whether to raise a new exception]
              # Not raising a new exception, so reraise
              ctxt.reraise = True
    """
    def __init__(self, reraise=True, logger=None):
        self.reraise = reraise
        if logger is None:
            logger = logging.getLogger()
        self.logger = logger

    def __enter__(self):
        self.type_, self.value, self.tb, = sys.exc_info()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            if self.reraise:
                self.logger.error(_LE('Original exception being dropped: %s'),
                                  traceback.format_exception(self.type_,
                                                             self.value,
                                                             self.tb))
            return False
        if self.reraise:
            six.reraise(self.type_, self.value, self.tb)


def forever_retry_uncaught_exceptions(infunc):
    def inner_func(*args, **kwargs):
        last_log_time = 0
        last_exc_message = None
        exc_count = 0
        while True:
            try:
                return infunc(*args, **kwargs)
            except Exception as exc:
                this_exc_message = six.u(str(exc))
                if this_exc_message == last_exc_message:
                    exc_count += 1
                else:
                    exc_count = 1
                # Do not log any more frequently than once a minute unless
                # the exception message changes
                cur_time = int(time.time())
                if (cur_time - last_log_time > 60 or
                        this_exc_message != last_exc_message):
                    logging.exception(
                        _LE('Unexpected exception occurred %d time(s)... '
                            'retrying.') % exc_count)
                    last_log_time = cur_time
                    last_exc_message = this_exc_message
                    exc_count = 0
                # This should be a very rare event. In case it isn't, do
                # a sleep.
                time.sleep(1)
    return inner_func
