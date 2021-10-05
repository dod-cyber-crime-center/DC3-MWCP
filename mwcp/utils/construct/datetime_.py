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
class EpochTimeAdapter(Adapter):
    r"""
    Adapter to convert time_t, EpochTime, to an isoformat

    >>> EpochTimeAdapter(construct.Int32ul, tz=datetime.timezone.utc).parse(b'\xff\x93\x37\x57')
    '2016-05-14T21:09:19+00:00'
    >>> EpochTimeAdapter(construct.Int32ul).parse(b'\xff\x93\x37\x57')
    '2016-05-14T17:09:19'
    """
    def __init__(self, subcon, tz=None):
        """
        :param tz: Optional timezone object, default is localtime
        :param subcon: subcon to parse EpochTime.
        """
        super(EpochTimeAdapter, self).__init__(subcon)
        self._tz = tz

    def _decode(self, obj, context, path):
        return datetime.datetime.fromtimestamp(obj, tz=self._tz).isoformat()


# Add common helpers
EpochTime = EpochTimeAdapter(Int32ul)
EpochTimeUTC = EpochTimeAdapter(construct.Int32ul, tz=datetime.timezone.utc)
