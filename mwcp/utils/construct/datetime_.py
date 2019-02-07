"""
Date/Time constructs
"""

from __future__ import absolute_import

import datetime

from .version28 import *


# TODO: Implement _encode.
class _DateTimeDateDataAdapter(Adapter):
    r"""
    Adapter for a C# DateTime.dateData object to DateTime format. Obtain the DateTime.Ticks and the DateTime.Kind
    property to format datetime.


    >>> _DateTimeDateDataAdapter(Int64sl).parse('\x80\xb4N3\xd1\xd4\xd1H')
    '2014-11-23 01:09:01 UTC'
    """
    def _decode(self, obj, context, path):
        ticks = obj & 0x3fffffffffffffff
        kind = (obj >> 62) & 0x03
        converted_ticks = datetime.datetime(1, 1, 1) + datetime.timedelta(microseconds=ticks / 10)
        if kind == 0:
            return converted_ticks.strftime("%Y-%m-%d %H:%M:%S")
        elif kind == 1:
            return converted_ticks.strftime("%Y-%m-%d %H:%M:%S UTC")
        elif kind == 2:
            return converted_ticks.strftime("%Y-%m-%d %H:%M:%S Local")


DateTimeDateData = _DateTimeDateDataAdapter(Int64sl)


# TODO: Implement _encode
class _EpochTimeAdapter(Adapter):
    r"""
    Adapter to convert time_t, EpochTime, to an isoformat

    >>> _EpochTimeAdapter(Int32ul).parse('\xff\x93\x37\x57')
    '2016-05-14T17:09:19'
    """
    def _decode(self, obj, context, path):
        return datetime.datetime.fromtimestamp(obj).isoformat()

# Hide the adapter
EpochTime = _EpochTimeAdapter(Int32ul)