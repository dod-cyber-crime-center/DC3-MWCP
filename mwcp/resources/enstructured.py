#!/usr/bin/env python

"""
enstructured -- library for extracting data from data stream using struct like specifications but
supporting powerful operations including dynamic structure definitions and nested structures.
"""

import sys
import datetime
import json
import struct
import binascii
import re
import numbers

try:
    import yaml
    yaml_available = True
except ImportError:
    yaml_available = False

UINT8 = "uint8"
UINT16 = "uint16"
UINT32 = "uint32"
UINT64 = "uint64"

BYTE = "uint8"
WORD = "uint16"
DWORD = "uint32"
QWORD = "uint64"
ULONG = "uint32"
ULONGLONG = "uint64"

INT8 = "int8"
INT16 = "int16"
INT32 = "int32"
INT64 = "int64"
LONG = "int32"
LONGLONG = "int64"


FLOAT = "float"
DOUBLE = "double"
FLOAT32 = "float"
FLOAT64 = "double"

BYTES = "bytes"
RAW = "bytes"

REGEX = "regex"

STR = "str"
STR8 = "str"
WCSTR = "str16"
STR16 = "str16"
STR32 = "str32"

NULL = "null"

SUBFIELD = "subfield"
SUBFIELDLIST = "subfieldlist"
MAPSUBFIELD = "mapsubfield"

BIG_ENDIAN = ">"
LITTLE_ENDIAN = "<"
SYSTEM_ENDIAN = "="

MAXINT = sys.maxint

COLORPALLETTE = [
    '#00ff00', '#0000ff', '#00ffff', '#ff0000', '#ffff00', '#ff00ff',
    '#008000', '#000080', '#008080', '#00ff80', '#0080ff', '#800000', '#808000', '#80ff00',
    '#800080', '#808080', '#80ff80', '#8000ff', '#8080ff', '#80ffff', '#ff8000', '#ff0080',
    '#ff8080', '#ffff80', '#ff80ff',
    '#004000', '#00bf00', '#000040', '#004040', '#008040', '#00bf40', '#00ff40', '#004080',
    '#00bf80', '#0000bf', '#0040bf', '#0080bf', '#00bfbf', '#00ffbf', '#0040ff', '#00bfff',
    '#400000', '#404000', '#408000', '#40bf00', '#40ff00', '#400040', '#404040', '#408040',
    '#40bf40', '#40ff40', '#400080', '#404080', '#408080', '#40bf80', '#40ff80', '#4000bf',
    '#4040bf', '#4080bf', '#40bfbf', '#40ffbf', '#4000ff', '#4040ff', '#4080ff', '#40bfff',
    '#40ffff', '#804000', '#80bf00', '#800040', '#804040', '#808040', '#80bf40', '#80ff40',
    '#804080', '#80bf80', '#8000bf', '#8040bf', '#8080bf', '#80bfbf', '#80ffbf', '#8040ff',
    '#80bfff', '#bf0000', '#bf4000', '#bf8000', '#bfbf00', '#bfff00', '#bf0040', '#bf4040',
    '#bf8040', '#bfbf40', '#bfff40', '#bf0080', '#bf4080', '#bf8080', '#bfbf80', '#bfff80',
    '#bf00bf', '#bf40bf', '#bf80bf', '#bfbfbf', '#bfffbf', '#bf00ff', '#bf40ff', '#bf80ff',
    '#bfbfff', '#bfffff', '#ff4000', '#ffbf00', '#ff0040', '#ff4040', '#ff8040', '#ffbf40',
    '#ffff40', '#ff4080', '#ffbf80', '#ff00bf', '#ff40bf', '#ff80bf', '#ffbfbf', '#ffffbf',
    '#ff40ff', '#ffbfff']

HTML_BEGIN = """
<html>
<head>
<meta http-equiv=Content-Type content="text/html; charset=windows-1252">
<meta name=Generator content="Microsoft Word 14 (filtered)">
<style>
<!--
 /* Font Definitions */
 @font-face
	{font-family:Courier;
	panose-1:2 7 4 9 2 2 5 2 4 4;}
@font-face
	{font-family:"Cambria Math";
	panose-1:2 4 5 3 5 4 6 3 2 4;}
@font-face
	{font-family:Calibri;
	panose-1:2 15 5 2 2 2 4 3 2 4;}
 /* Style Definitions */
 p.MsoNormal, li.MsoNormal, div.MsoNormal
	{margin:0in;
	margin-bottom:.0001pt;
	font-size:11.0pt;
	font-family:"Times New Roman","serif";}
h1
	{mso-style-link:"Heading 1 Char";
	margin:0in;
	margin-bottom:.0001pt;
	page-break-after:avoid;
	font-size:16.0pt;
	font-family:"Calibri","sans-serif";
	color:#943634;}
h3
	{mso-style-link:"Heading 3 Char";
	margin-top:10.0pt;
	margin-right:0in;
	margin-bottom:0in;
	margin-left:0in;
	margin-bottom:.0001pt;
	page-break-after:avoid;
	font-size:11.0pt;
	font-family:"Times New Roman","serif";}
p.MsoNoSpacing, li.MsoNoSpacing, div.MsoNoSpacing
	{mso-style-link:"No Spacing Char";
	margin:0in;
	margin-bottom:.0001pt;
	font-size:11.0pt;
	font-family:"Calibri","sans-serif";}
span.Heading1Char
	{mso-style-name:"Heading 1 Char";
	mso-style-link:"Heading 1";
	color:#943634;
	font-weight:bold;}
span.Heading3Char
	{mso-style-name:"Heading 3 Char";
	mso-style-link:"Heading 3";
	font-family:"Times New Roman","serif";
	font-weight:bold;}
span.NoSpacingChar
	{mso-style-name:"No Spacing Char";
	mso-style-link:"No Spacing";
	font-family:"Calibri","sans-serif";}
.MsoChpDefault
	{font-family:"Calibri","sans-serif";}
.MsoPapDefault
	{margin-bottom:10.0pt;
	line-height:115%;}
@page WordSection1
	{size:8.5in 11.0in;
	margin:1.0in 1.0in 1.0in 1.0in;}
div.WordSection1
	{page:WordSection1;}
-->
</style>
</head>
<body lang=EN-US>
<div class=WordSection1>
<p class=MsoNormal style='background:#FFFFFF'><span style='font-size:8.0pt;
font-family:"Courier New"'>&nbsp;offset&nbsp;|&nbsp;&nbsp;0&nbsp;&nbsp;1&nbsp;&nbsp;2&nbsp;&nbsp;3&nbsp;&nbsp;4&nbsp;&nbsp;5&nbsp;&nbsp;6&nbsp;&nbsp;7&nbsp;&nbsp;8&nbsp;&nbsp;9&nbsp;&nbsp;a&nbsp;&nbsp;b&nbsp;&nbsp;c&nbsp;&nbsp;d&nbsp;&nbsp;e&nbsp;&nbsp;f&nbsp;|&nbsp;0123456789abcdef</span></p>
<p class=MsoNormal style='background:#FFFFFF'><span style='font-size:8.0pt;
font-family:"Courier New"'>&nbsp;------ |  -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --  |  ----------------</span></p>
"""

HTML_TABLE_START = """
<table class=MsoNormalTable border=1 cellspacing=0 cellpadding=0
 style='margin-left:5.4pt;border-collapse:collapse;border:none'>
 <tr>
  <td width=175 valign=top style='width:131.05pt;border:solid windowtext 1.0pt;
  background:#244061;padding:0in 5.4pt 0in 5.4pt'>
  <p class=MsoNoSpacing align=center style='text-align:center'><b><span
  style='font-size:9.0pt;font-family:"Times New Roman","serif";color:white'>Offset</span></b></p>
  </td>
  <td width=238 valign=top style='width:178.7pt;border:solid windowtext 1.0pt;
  border-left:none;background:#244061;padding:0in 5.4pt 0in 5.4pt'>
  <p class=MsoNoSpacing align=center style='text-align:center'><b><span
  style='font-size:9.0pt;font-family:"Times New Roman","serif";color:white'>Name</span></b></p>
  </td>
  <td width=218 valign=top style='width:163.65pt;border:solid windowtext 1.0pt;
  border-left:none;background:#244061;padding:0in 5.4pt 0in 5.4pt'>
  <p class=MsoNoSpacing align=center style='text-align:center'><b><span
  style='font-size:9.0pt;font-family:"Times New Roman","serif";color:white'>Value</span></b></p>
  </td>
 </tr>
"""


def extract_single_value(data, type, **params):
    """
    easily extract a single value

    pass in a type definition and optional parameters and return the value extracted from data

    data: buffer from which the value should be extracted
    type: an enstructed data type. Ex. enstructured.STR

    optional parameters, such as length = 16 or offset = 4 can be specified. These must be compatible with the specified type
    """
    return Extractor().extract_members(data=data, specification=[[type, 'single', params]])['single']['value']


def member_map(members, depth=1):
    """
    Return a dict indicating bytes that are covered by a member
        key: location in buffer--only exists for data covered by an extracted member
        value: name of member

    members: members dictionary
    depth: depth to recurse in assigning member names
    """

    membermap = {}
    for key in members:
        for i in range(members[key]['location'], members[key]['location'] + members[key]['length']):
            membermap[i] = key
    return membermap


def html_hex(data, members, depth=1, colors=COLORPALLETTE, title="Enstructured Hex Output"):
    membermap = member_map(members)

    html = []
    html.append(HTML_BEGIN)

    format_colors = []
    for i in range(len(colors)):
        bgcolor = colors[i]

        brightness = int(bgcolor[1:3], 16) * .299 + int(bgcolor[3:5], 16) * .587 + int(bgcolor[5:7], 16) * .114
        if brightness >= 128:
            textcolor = "#000000"
        else:
            textcolor = "#ffffff"
        format_colors.append([bgcolor, textcolor])

    for offset in range(0, len(data), 16):
        hextext = []
        for hexoffset in range(16):
            if offset + hexoffset < len(data):
                if (offset + hexoffset) in membermap:
                    index = members[membermap[offset + hexoffset]]['index'] % len(colors)
                    if hexoffset != 15 and (offset + hexoffset + 1) in membermap:
                        hextext.append('<span style=\'background:%s;color:%s\'>%02x&nbsp;</span>' % (format_colors[index][0], format_colors[index][1], ord(data[offset + hexoffset])))
                    else:
                        hextext.append('<span style=\'background:%s;color:%s\'>%02x</span>&nbsp;' % (format_colors[index][0], format_colors[index][1], ord(data[offset + hexoffset])))
                else:
                    hextext.append('%02x&nbsp;' % (ord(data[offset + hexoffset])))
            else:
                hextext.append('&nbsp;&nbsp;&nbsp;')

        asciitext = []
        for hexoffset in range(16):
            if offset + hexoffset < len(data):
                if ord(data[offset + hexoffset]) > 32 and ord(data[offset + hexoffset]) < 127:
                    ascii = data[offset + hexoffset]
                else:
                    ascii = "."
                if (offset + hexoffset) in membermap:
                    index = members[membermap[offset + hexoffset]]['index'] % len(colors)
                    asciitext.append('<span style=\'background:%s;color:%s\'>%s</span>' % (format_colors[index][0], format_colors[index][1], ascii))
                else:
                    asciitext.append('%s' % ascii)
            else:
                asciitext.append('&nbsp;')
        asciitext = map(lambda x: '&#%d' % ord(x) if len(x) == 1 else x, asciitext)
        html.append('    <p class=MsoNormal style=\'background:#FFFFFF\'><span style=\'font-size:8.0pt;font-family:"Courier New"\'>&nbsp;%06x&nbsp;|&nbsp;%s|&nbsp;%s</span></p>\n' % (offset, ''.join(hextext), ''.join(asciitext)))

    html.append('<p class=MsoNormal>&nbsp;</p>\n')

    html.append(HTML_TABLE_START)

    for name in ordered_member_names(members):
        index = members[name]['index'] % len(colors)
        html.append(r" <tr>  <td width=175 valign=top style='width:131.05pt;border:solid windowtext 1.0pt;  border-top:none;padding:0in 5.4pt 0in 5.4pt'>  <p class=MsoNoSpacing><span style='font-size:8.0pt;font-family:""Courier New"";  '>%06x</span></p>  </td>" % members[name]['location'])

        html.append(r"<td width=238 valign=top style='width:178.7pt;border-top:none;border-left:  none;border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;  padding:0in 5.4pt 0in 5.4pt'>  <p class=MsoNoSpacing><span style='font-size:8.0pt;font-family:""Courier New"";background:%s;color:%s'>%s</span></p>  </td>" % (format_colors[index][0],format_colors[index][1], name))
        if 'formatted_value' in members[name]:
            display_value = members[name]['formatted_value']
        else:
            display_value = members[name]['value']
        if isinstance(display_value, basestring) or isinstance(display_value, numbers.Number):
            # TODO: handle encoding issues here.
            display_value = str(display_value)
        else:
            display_value = re.sub("\n", "<br />", pformat(filter_formatted_values(display_value)))

        html.append(r"<td width=218 valign=top style='width:163.65pt;border-top:none;border-left:  none;border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;  padding:0in 5.4pt 0in 5.4pt'>  <p class=MsoNoSpacing><span style='font-size:8.0pt;font-family:""Courier New""'>%s</span></p>  </td> </tr>" % (display_value))
    html.append('</table>\n')
    html.append('</div>\n')
    html.append('</body>\n')
    html.append('</html>\n')

    return "".join(html)


def ordered_member_names(members):
    """
    Return a list of top level member names
    """
    ordered_member_names = []
    ordered_members = member_indexes(members)
    for index in sorted(ordered_members):
        ordered_member_names.append(ordered_members[index])
    return ordered_member_names


def member_indexes(members):
    index = {}
    for member in members:
        # used to use index, now use location, skip if there is no location
        if 'location' in members[member]:
            index[members[member]['location']] = member
    return index


def filter_formatted_values(members, order=True):
    """
    return structure of just formatted values, no offsets, indexes, etc

    by default, order elements by turning dicts into lists of key:value dicts
    this makes iterating/displaying much easier, but makes accessing specific keys more difficult
    """
    if isinstance(members, dict):
        if order:
            return_val = []
        else:
            return_val = {}

        if 'formatted_value' in members:
            return filter_formatted_values(members['formatted_value'], order)
        elif 'value' in members:
            return filter_formatted_values(members['value'], order)
        else:
            if order:
                for key in ordered_member_names(members):
                    return_val.append({key: filter_formatted_values(members[key], order)})
            else:
                for key in members:
                    return_val[key] = filter_formatted_values(members[key], order)
        return return_val
    if isinstance(members, list):
        return_val = []
        for value in members:
            return_val.append(filter_formatted_values(value, order))
        return return_val
    return members


def pformat(members):
    """
    pretty format objects for human consumption

    use yaml if available, then fall back to modified json
    """

    if yaml_available:
        return yaml.safe_dump(members)
    else:
        return re.sub(r"""\n[}\]]""", "", re.sub(r""" *[{}\[\]],? *\n""", "", json.dumps(members, indent = 2)))


def is_leaf(member):
    """
    determine is member is a leaf node or not
    """
    if not isinstance(member, dict):
        return False
    if 'value' not in member:
        return False
    if 'value' in member:
        value = member['value']
        if value:
            if isinstance(value, dict):
                for keys in value:
                    if "value" in value[keys]:
                        return False
            if isinstance(value, list):
                for index in range(len(value)):
                    if isinstance(value[index], dict):
                        for embed_value in value[index]:
                            if isinstance(value[index][embed_value], dict):
                                if "value" in value[index][embed_value]:
                                    return False
    return True


def fix_member_indexes(members):
    """
    fix member indexes, based on location. Useful after flattening, for example
    """
    i = 0
    for key in ordered_member_names(members):
        members[key]['index'] = i
        i = i + 1
    return members


def flatten_members(members, path="", depth=99):
    """
    return a list of flattened member, up to depth
    """
    if depth:
        flat_members = {}
        if isinstance(members, dict):
            if 'value' in members:
                value = members['value']
                # dictionary with members
                if isinstance(value, dict) and contains_members(value):
                    for key in value:
                        subpath = ".".join((path, key)).lstrip(".")
                        new_members = flatten_members(value[key], path=subpath, depth=depth - 1)
                        for new_key in new_members:
                            flat_members[new_key] = new_members[new_key]

                # list with members
                elif isinstance(value, list) and contains_members(value):
                    for key in range(len(value)):
                        subpath = ".".join((path,str(key))).lstrip(".")
                        if depth > 1:
                            new_members = flatten_members(value[key], path=subpath, depth=depth -1)
                            for new_key in new_members:
                                flat_members[new_key] = new_members[new_key]
                        else:
                            # construct a member (this doesn't actually exist) (or just traverse
                            # another layer?
                            this_member = {}
                            this_member['value'] = value[key]
                            this_member['index'] = key
                            this_member_order = ordered_member_names(value[key])
                            # set location and length
                            if 'location' in value[key][this_member_order[0]]:
                                this_member['location'] = value[key][this_member_order[0]]['location']
                                if 'length' in value[key][this_member_order[-1]] and 'location' in value[key][this_member_order[-1]]:
                                    this_member['length'] = value[key][this_member_order[-1]]['location'] + value[key][this_member_order[-1]]['length'] - value[key][this_member_order[0]]['location']
                            flat_members[subpath] = this_member

                # anything else--ex. leaf node, other data type
                else:
                    flat_members[path] = members

            else:
                # just a container
                for key in members:
                    subpath = ".".join((path, key)).lstrip(".")
                    submembers = flatten_members(members[key], path=subpath, depth=depth - 1)
                    # this will always be dict members
                    for subkey in submembers:
                        flat_members[subkey] = submembers[subkey]
        return flat_members
    else:
        if path:
            return {path: members}
        else:
            return members


def contains_members(members):
    """
    validate that the structure passed (list or dict) contains members (have values in them)
    """
    if isinstance(members, dict):
        for key in members:
            submember = members[key]
            if isinstance(submember, dict):
                if "value" in submember:
                    return True
                if contains_members(submember):
                    return True
    if isinstance(members, list):
        for key in range(len(members)):
            submember = members[key]
            if isinstance(submember, dict):
                if "value" in submember:
                    return True
                if contains_members(submember):
                    return True
    return False


class Extractor(object):
    """
    Extractor class: object for parsing from a data blob

    """

    def __init__(self,
                 data='',
                 specification='',
                 external_data=None,
                 endian=None,
                 location=0,
                 parent=None,
                 ignored=False
                 ):
        self.data = data
        self.specification = specification
        self.external_data = external_data

        self.members = {}
        self.membernames = []
        self.__currentlocation = location
        self.__currentspecindex = 0
        # we default to little instead of system default to make specifications portable
        # across systems
        self.__endianflag = LITTLE_ENDIAN
        self.__currentmember = None
        self.__parent = parent
        self.__baselocation = location
        self.ignored = ignored

        if endian:
            if endian == BIG_ENDIAN or endian == LITTLE_ENDIAN or endian == SYSTEM_ENDIAN:
                self.__endianflag = endian
            else:
                raise ValueError("Invalid endian specification: %s" % (endian))

    def generate_id(self):
        return "member%i" % (self.__currentspecindex)

    def extract_members(self, data='', specification='', location=0, external_data=None, endian=None, parent=None):
        """
        Extractor execution method
        extract all the members from data that are specified by specification
        """
        # TODO? remove this override capability?
        if data:
            self.data = data
        if specification:
            self.specification = specification
        if external_data:
            self.external_data = external_data
        if endian:
            if endian == BIG_ENDIAN or endian == LITTLE_ENDIAN or endian == SYSTEM_ENDIAN:
                self.__endianflag = endian
            else:
                raise ValueError("Invalid endian specification: %s" % (endian))
        if parent:
            self.__parent = parent

        if location:
            self.__currentlocation = location
            self.__baselocation = location

        for spec in self.specification:
            params = {}

            if len(spec) > 0 and len(spec) <= 3:
                if len(self.data) < self.__currentlocation:
                    break
                # TODO: check for valid type here?
                type = spec[0]

                if len(spec) >= 2:
                    name = spec[1]
                    if name in self.members:
                        raise ValueError("Duplicate member name: %s" % (name))
                    if name == "value" or "." in name:
                        raise ValueError('Invalid member name: name must not be "value" or contain "."')
                    if len(spec) == 3:
                        # TODO validate that this is dictionary?
                        params = self.__eval_replace(spec[2])
                else:
                    name = self.generate_id()
                try:
                    self.extract_member(type, name, params)
                except:
                    # TODO: handle this better. Create elements in the json
                    return None

            else:
                raise TypeError("Member specification %i is invalid" % (self.__currentspecindex))

        todelete = []
        for i in self.members:
            if self.members[i]['ignore']:
                todelete.append(i)
        for i in todelete:
            del self.members[i]

        return self.members

    def extract_member(self, type, name, params):
        """
        extract a single member
        """

        skip = 0
        if "skip" in params:
            self.__currentlocation = self.__currentlocation + params['skip']
            skip = params['skip']
            params.pop('skip', None)

        # For a situation in which the buffer for strings in a list may vary causing
        # null bytes to be between each string
        if "skipnull" in params and params['skipnull']:
            while self.data[self.__currentlocation] == '\0':
                self.__currentlocation += 1
            params.pop('skipnull', None)

        if "location" in params:
            self.__currentlocation = params['location']
            params.pop('location', None)
        if "offset" in params:
            self.__currentlocation = params['offset'] + self.__baselocation
            params.pop('offset', None)

        formatfunc = None
        if "formatter" in params:
            formatfunc = params.pop('formatter', None)

        self.members[name] = {"index": self.__currentspecindex, "type": type, "location": self.__currentlocation}

        if skip:
            self.members[name]['skip'] = skip

        if params:
            self.members[name]['params'] = params
            if 'description' in params:
                self.members[name]['description'] = params.pop('description', "")

        self.members[name]['ignore'] = params.pop('ignore', False)

        self.membernames.append(name)
        self.__currentmember = self.members[name]

        getattr(self, "extract_%s" % (type))(**params)

        if formatfunc and hasattr(formatfunc, '__call__'):
            self.members[name]['formatted_value'] = formatfunc(self.members[name]['value'])
            self.members[name]['formatter'] = formatfunc.__name__
        else:
            if not contains_members(self.members[name]['value']):
                self.members[name]['formatted_value'] = self.members[name]['value']

        # do this here or begining?
        self.__currentmember['offset'] = self.__currentlocation - self.__baselocation - self.__currentmember['length']
        self.__currentspecindex = self.__currentspecindex + 1
        self.__currentmember = None

    def extract_uint8(self):
        """
        Extract a number (uint8)
        """
        self.__unpack_number()

    def extract_int8(self):
        self.__unpack_number()

    def extract_uint16(self):
        self.__unpack_number()

    def extract_int16(self):
        self.__unpack_number()

    def extract_uint32(self):
        self.__unpack_number()

    def extract_int32(self):
        self.__unpack_number()

    def extract_uint64(self):
        self.__unpack_number()

    def extract_int64(self):
        self.__unpack_number()

    def extract_float(self):
        self.__unpack_number()

    def extract_double(self):
        self.__unpack_number()

    def extract_bytes(self, length=1):
        """
        Extract a data blob

        length: length of buffer in bytes
        """
        self.__unpack_buffer(length)

    def extract_regex(self, regex):
        """
        Extract data covered by a regex.

        location: place to start searching for regex. If match occurs, set location and length
        to be values of match regex is a compiled regex program
        """
        self.__unpack_regex(regex)

    def extract_str(self, length=-1, encoding="utf8"):
        """
        Extract and decode a string

        The value is returneed as unicode object.

        length: length of buffer in bytes. if length is set to -1, then we search for a nullterminator.
        encoding: encoding to try
        """
        self.__unpack_string(length, encoding)

    def extract_str16(self, length=-1, encoding="utf16"):
        self.__unpack_string(length, encoding)

    def extract_str32(self, length=-1, encoding="utf32"):
        self.__unpack_string(length, encoding)

    def extract_null(self, **params):
        """
        Null extraction. Allows for calculations, markers, etc with no extraction of data but
        reporting of the value in params as value and position of current_location.

        value: value of this data item
        """
        self.__unpack_null(**params)

    def extract_subfield(self, spec):
        """
        Extract a subfield. The value of this item is a dictionary with the subfields embedded
        inside.

        We use a new Extractor object for this operation..

        spec: the extraction specification to use

        """
        self.__unpack_subfield(spec, count=1, maxlength=MAXINT)

    def extract_subfieldlist(self, spec, count=MAXINT, maxlength=MAXINT):
        """
        Extract a list of subfields. The value is list of subfields with each subfields being a
        dictionary.

        either maxlength or count should be specified.

        spec: the extraction specification to use
        maxlength: maximum length of the whole list of subfields, default: MAXINT
        count: number of subfields to extract, default: MAXINT

        """
        self.__unpack_subfield(spec, count, maxlength)

    def extract_mapsubfield(self, key, specmap):
        """
        Extract a subfield based on lookup. If key is found in specmap, that spec is extracted

        key: key to use for specmap lookup. This is usually an interpretted value referencing a previously extracted field.
        specmap: a mapping (dictionary) of key: specifiction pairs
        """
        self.__unpack_mapsubfield(key, specmap)

    def __unpack_number(self):

        formatchars = {"uint8": "B",
                       "int8": "b",
                       "uint16": "H",
                       "int16": "h",
                       "uint32": "I",
                       "int32": "i",
                       "uint64": "Q",
                       "int64": "q",
                       "float": "f",
                       "double": "d",
                       }

        formatlengths = {"uint8": 1,
                         "int8": 1,
                         "uint16": 2,
                         "int16": 2,
                         "uint32": 4,
                         "int32": 4,
                         "uint64": 8,
                         "int64": 8,
                         "float": 4,
                         "double": 8,
                         }

        self.__currentmember['value'] = struct.unpack(self.__endianflag + formatchars[self.__currentmember['type']],
                                                      self.data[self.__currentlocation:self.__currentlocation +
                                                      formatlengths[self.__currentmember['type']]])[0]
        self.__currentlocation = self.__currentlocation + formatlengths[self.__currentmember['type']]
        self.__currentmember['length'] = formatlengths[self.__currentmember['type']]

    def __unpack_buffer(self, length):
        self.__currentmember['value'] = self.data[self.__currentlocation:self.__currentlocation + length]
        self.__currentmember['length'] = length
        self.__currentlocation = self.__currentlocation + length

    def __unpack_string(self, length, encoding):

        formatlengths = {"str": 1,
                         "str16": 2,
                         "str32": 4
                         }

        nulloffset = 0

        if length == -1:
            length = self.__aligned_find(self.data,
                                         str("\x00" * formatlengths[self.__currentmember['type']]),
                                         formatlengths[self.__currentmember['type']],
                                         self.__currentlocation)

            self.__currentmember['debug'] = {'find_len': length}
            if length == -1:
                length = len(self.data) - self.__currentlocation
            else:
                nulloffset = formatlengths[self.__currentmember['type']]
                length = length + formatlengths[self.__currentmember['type']] - self.__currentlocation

        self.__currentmember['length'] = length
        self.__currentmember['value'] = self.__unicode_rstrip_null(unicode(self.data[self.__currentlocation:self.__currentlocation + length - nulloffset], encoding=encoding, errors='replace'))
        self.__currentlocation = self.__currentlocation + length

    def __unpack_null(self, **params):
        if 'value' in params:
            self.__currentmember['value'] = params['value']
        self.__currentmember['length'] = 0

    def __unpack_mapsubfield(self, key, specmap):
        if key in specmap:
            self.__unpack_subfield(specmap[key], count=1, maxlength=MAXINT)
        else:
            self.__currentmember['value'] = {}
            location = self.__currentlocation
            self.__currentmember['length'] = 0

    def __unpack_subfield(self, spec, count, maxlength):
        if count == 1:
            extractor = self.__class__(data=self.data, specification=spec, location=self.__currentlocation,
                                       external_data=self.external_data, endian=self.__endianflag,
                                       parent=self)
            self.__currentmember['value'] = extractor.extract_members()
            location = extractor.__currentlocation
        else:
            subfieldlist = []
            location = self.__currentlocation
            fieldcount = 0
            while (fieldcount < count and location < len(self.data)):
                extractor = self.__class__(data=self.data, specification=spec, location=location,
                                           external_data=self.external_data, endian=self.__endianflag,
                                           parent=self)

                if extractor.__currentlocation - self.__currentlocation >= maxlength:
                    break

                extracted = extractor.extract_members()
                if extracted:
                    subfieldlist.append(extracted)
                location = extractor.__currentlocation
                fieldcount = fieldcount + 1

            self.__currentmember['value'] = subfieldlist
            self.__currentmember['count'] = fieldcount

        self.__currentmember['length'] = location - self.__currentlocation
        self.__currentlocation = location

    def __unpack_regex(self, regex):
        match = regex.search(self.data[self.__currentmember['location']:])
        if match:
            self.__currentmember['location'] = self.__currentmember['location'] + match.start()
            self.__currentmember['length'] = match.end() - match.start()
            self.__currentmember['value'] = match.group(0)
            self.__currentlocation = self.__currentmember['location'] + self.__currentmember['length']
        else:
            self.__currentmember['length'] = 0
            self.__currentmember['value'] = ""

    def __parent_members(self):
        parents = []
        current = self
        while(current.__parent):
            current = current.__parent
            parents.append(current.members)
        return parents

    def __eval_replace(self, params):
        newparams = {}
        for key in params:
            value = params[key]
            if isinstance(value, basestring) and value[0] == "`" and value[-1] == "`":
                newparams[key] = eval(value[1:-1], {}, {"members": self.members,
                                                        "parent_members": self.__parent_members(),
                                                        "params": params,
                                                        "current_location": self.__currentlocation,
                                                        "base_location": self.__baselocation,
                                                        "current_offset": self.__currentlocation - self.__baselocation,
                                                        "external_data": self.external_data,
                                                        "data": self.data})
            else:
                newparams[key] = value
        return newparams

    def __unicode_rstrip_null(self, inputstring):
        outputstring = inputstring
        while len(outputstring) >= 1 and outputstring[-1] == u'\x00':
            outputstring = outputstring[:-1]
        return outputstring

    def __aligned_find(self, input, needle, wordlength=1, startoffset=0):
        while startoffset < len(input):
            pos = input.find(needle, startoffset)
            if ((pos - startoffset) % wordlength) == 0 or pos == -1:
                return pos
            else:
                startoffset = pos + wordlength - ((pos - startoffset) % wordlength)
        return -1


def __bitmask_values(self, mask):
    values = []
    total = 0
    i = 0
    while(total < mask):
        test_mask = 2 ** i
        if test_mask & mask == test_mask:
            values.insert(0, test_mask)
        total = total + test_mask
        i = i + 1
    return values


def format_timestamp(value):
    """
    Format a (unix) timestamp (number) as an isotime.
    """
    return datetime.datetime.fromtimestamp(value).isoformat()


def format_filetime(value):
    """
    Format a windows filetime (number) as an isotime.
    """
    return datetime.datetime.fromtimestamp((value) / 10000000 - 11644473600).isoformat()


def format_enum_factory(definition):
    """
    Factory to create enum formatter.

    Map usually integer values to other, usually string values.

    definition is mapping where key is the item looked up and the value is the item returns
    """
    def formatter_enum(value):
        if definition:
            if value in definition:
                return definition[value]
    return formatter_enum


def format_bitmask_factory(definition):
    """
    Factory for bitmask formatters
    Map combinations of powers of 2 integers to other values, usually strings. Returns list of output values

    definition is mapping where key is the item looked up and the value is the item returns
    """
    def format_bitmask(value):
        bitmaskvalues = __bitmask_values(value)
        return_values = []
        if definition:
            for bitmaskvalue in bitmaskvalues:
                if bitmaskvalue in map:
                    return_values.append(map[bitmaskvalue])
        return return_values
    return format_bitmask


def format_emptystring(value):
    """
    Returns value of empty string

    Nice way to get rid of values that you don't want to see in output but otherwise need to be defined in
    structure, for example, to use offsets.
    """
    return ""


def format_replace_factory(newvalue):
    """
    Factory for creating formatter that simply return a constant value

    Nice way to get rid of values that you don't want to see in output but otherwise need to be defined in
    structure, for example, to use offsets.
    """
    def format_replace(value):
        return newvalue
    return format_replace


def format_hex(value):
    """
    Format a binary blob as hex encoded value

    """
    return "0x%s" % (binascii.hexlify(value))


def format_hex_int(value):
    """
    Format an integer as hex
    """
    return "0x%x" % (value)


def format_boolean(value):
    """
    Function Description:
        Formats a value as a boolean string, True or False

    Return Value:
        Formatted string
    """
    return str(bool(value))


def format_ipv4(hex_ip):
    """
    Function Description:
        Converts specified DWORD value into an IP address.

    Arguments:
        hex_ip: The DWORD hex representation of an IP address

    Return Value:
        The formatted IP address
    """
    return '{:d}.{:d}.{:d}.{:d}'.format(*map(lambda x: ord(x), hex_ip))


def format_mac(mac_address):
    """
    Function Description:
        Converts MAC address bytes into a formatted MAC address

    Arguments:
        mac_address: The 6-bytes of a MAC address

    Return Value:
        The formatted MAC address
    """
    return '{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}'.format(*map(lambda x: ord(x), mac_address))
