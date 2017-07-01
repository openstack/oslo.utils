===========
 timeutils
===========

Using a stopwatch (as a context manager)
----------------------------------------

::

    >>> from oslo_utils import timeutils
    >>> import time
    >>>
    >>> def slow_routine(delay):
    ...    def i_am_slow():
    ...       time.sleep(delay)
    ...    return i_am_slow
    ...
    >>>
    >>> half_sec_func = slow_routine(0.5)
    >>> with timeutils.StopWatch() as w:
    ...    half_sec_func()
    ...
    >>> print(w.elapsed())
    0.500243999995


Manually using a stopwatch
--------------------------

::

    >>> from oslo_utils import timeutils
    >>> import time
    >>> w = timeutils.StopWatch()
    >>> w.start()
    <oslo_utils.timeutils.StopWatch object at 0x2b85a0ab7590>
    >>> time.sleep(0.1)
    >>> time.sleep(0.1)
    >>> time.sleep(0.1)
    >>> time.sleep(0.1)
    >>> w.stop()
    <oslo_utils.timeutils.StopWatch object at 0x2b85a0ab7590>
    >>> w.elapsed()
    13.96467600017786

Tracking durations with a stopwatch
-----------------------------------

::

    >>> from oslo_utils import timeutils
    >>> w = timeutils.StopWatch(duration=10)
    >>> w.start()
    <oslo_utils.timeutils.StopWatch object at 0x2b85a7940a10>
    >>> w.elapsed()
    2.023942000232637
    >>> w.leftover()
    4.648160999640822
    >>> w.leftover()
    3.5522090001031756
    >>> w.leftover()
    3.0481000002473593
    >>> w.leftover()
    2.1918740002438426
    >>> w.leftover()
    1.6966530000790954
    >>> w.leftover()
    1.1202940000221133
    >>> w.leftover()
    0.0
    >>> w.expired()
    True

Tracking and splitting with a stopwatch
---------------------------------------

::

    >>> from oslo_utils import timeutils
    >>> w = timeutils.StopWatch()
    >>> w.start()
    <oslo_utils.timeutils.StopWatch object at 0x2ba75c12b050>
    >>> w.split()
    Split(elapsed=3.02423300035, length=3.02423300035)
    >>> w.split()
    Split(elapsed=6.44820600003, length=3.42397299968)
    >>> w.split()
    Split(elapsed=7.9678720003, length=1.51966600027)
    >>> w.splits
    (Split(elapsed=3.02423300035, length=3.02423300035), Split(elapsed=6.44820600003, length=3.42397299968), Split(elapsed=7.9678720003, length=1.51966600027))
    >>> w.stop()
    <oslo_utils.timeutils.StopWatch object at 0x2ba75c12b050>
    >>> w.elapsed()
    16.799759999848902
    >>> w.splits
    (Split(elapsed=3.02423300035, length=3.02423300035), Split(elapsed=6.44820600003, length=3.42397299968), Split(elapsed=7.9678720003, length=1.51966600027))
