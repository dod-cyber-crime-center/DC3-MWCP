# Enstructured
enstructured is a library for parsing data. It facilitates parsing based on
struct-like data format specifications but adds capabilities such as:

- dynamic specifications based using evals including references to previously extracted data
- nested definitions
- regular expression based elements
- formatting functions to customize extracted data

enstructured is designed to make re-use of specifications easy.

See enstructured_example.py for an example of parsing a PE header. Examples from this file (denoted by comments) are referenced throughout this document.

## Use

enstructured is focused around data specifications. Each member in a specification is a tuple of a core data type, a name (which must be unique in the specification), and optional parameters. Some parameters are universally applicable and some only apply to specific data types. See Example 1. 

Data is extracted from a buffer by creating an Extractor object and running extract members. 
This returns a dictionary containing all the extracted members. See Example 7.

### Members dictionary

The core output of the enstructured library is a members dictionary, which contains the extracted specification members. The keys in this dictionary are the names used in the specification. 
For example, given the PE_HEADER example specification, where the first member is:

```python
[enstructured.STR,          "e_magic",                  {"length": 0x2, "description": "MZ header"}],
```

The member extracted would be as follows:
```python
pprint.pprint(members['e_magic'])

{'description': 'MZ header',
 'formatted_value': u'MZ',
 'index': 0,
 'length': 2,
 'location': 0,
 'offset': 0,
 'params': {'length': 2},
 'type': 'str',
 'value': u'MZ'}
```

The following are some of the keys found in each member which is a dictionary:
- value: the extracted value
- formatted_value: the value following any formatting.
- index: order of the member, zero indexed. A new counter is created for each substructure
- offset: offset relative to start of structure
- location: location relative to start of file 
- length: length of the member in bytes. This refers to the raw size of the element in the data buffer.
- type: data type


The members dictionary is designed to provide efficient access by key (member name) and is designed to be comprehensive in data included.
Transformation may be appropriate for displaying an overview of the extracted value. Example 8 demonstrates how to use the filter_formatted_values()
function to print a more easily consumable overview of the extracted values.

location and offset are different. Location is based on the start of the input buffer. Offset is based on the start of the structure. 
This distinction is important when structures are applied to a buffer at any location other than 0. This happens often when subfields
are employed. 

### Member data types

Enstructured provides a few core data types that can be used to build specifications.

The data types can be discovered by viewing the pydoc for enstructured. The Extractor class functions that begin with extract_ all operate on the associated data type. 
For example, extract_unit32() implements the uint32 data type. This data type is aliased with the constants DWORD, ULONG, and UINT32.
Most of the meanings of these data types are self explanatory. These function definitions also document the data type specific parameters used for extraction.

#### Numbers
The numerical data types are the most common and are straightforward. The returned value is a Number, i.e. an integer or a float.

#### Strings

String types are also used widely. String types are organized primarily by the width of the string. Ex. STR or STR8 for 8 bit strings, WCSTR or STR16 for 16 bit strings, and STR32 for 32 bit strings. 
The default encodings are utf8, utf16, and utf32 respectively but this can be overridden with the encoding parameter. If length isn't specified, the extractor assumes null termination and searches until
the appropriate null terminator is found. If length is specified it is used. In either case, null padding is removed from the end of the string. The string is returned
as a unicode object.

#### RAW and BYTES
The bytes types, aliased with RAW and BYTES, is useful for extracting raw binary blobs. The length of the data is almost always specified. This type is often used with formatters and can result in values that aren't printable.

#### REGEX
The regex type is used to apply regular expressions, whether for searching, capture, or both. The regex parameter should be a compiled regex object, ex. created by re.compile().
The location parameter specifies where the regex search starts. If a match is made, the location and length of the member are set to that of the match and the value is the raw data matched.

#### SUBFIELDS

The subfield types, subfield, subfieldlist, and mapsubfield allow the nesting of enstructured definitions. 

subfield is the nesting of a single specification within another. The parameter spec is used to provide the subordinate specification.
A new Extractor object is used for the subfield. The members extracted from the subfield are placed in the value of the subfield member.

subfieldlist allows the extraction of a list of subfields. Usually count or maxlength is specified. See Example 6 where the array of PE section headers is extracted as a list.

mapsubfield is used to select from among multiple subfields based on the value of the parameter key which is usually based on previously extracted data.
A dictionary of specifications arranged by key is provided in the specmap parameter. 
This type provides arbitrary conditional capability in enstructured specifications. 
A simple binary conditional (if statement) is created by using a map with keys of TRUE or FALSE and an evaluated statement that is used as the parameter key.
See Example 5 where a mapped subfield is used to select between the 32-bit or 64-bit version of the same structure.

#### NULL

The null data type does not extract any data from the buffer. It simply provides a placeholder for arbitrary operations. It takes a value parameter which is almost invariably an evaluated dynamic value.
This type is useful for situations where arbitrary operations need to be performed and it is desirable for these to be reported as a member value.

### Parameters

Enstructured specifications support parameters for each member. Some of these parameters are global, applying to all data types, while some are specific data types. 
Parameters can include values that run through the eval() function to allow dynamic specifications.

See Example 2 where various parameters are used.

data type specific parameters are defined in the function definition of the extract_ function for that data type.

The following parameters are broadly applicable parameters:

#### Offset

The offset parameter can be provided to specify the location where a member resides, relative to the start of the structure. 

#### Location

The location parameter can be provided to specify the location where a member resides,
relative to the start of the input buffer. 
Typically, offset should be used instead of location as it allows for relative locations
based on the structure location, but location may be used when it is important to use the
absolute location in the data buffer.

#### Skip

skip tells the parser to advance the specified number of bytes from the end of the last member before starting the current member.

#### Length

A large number of types support a length parameter which is specified in bytes.

#### Description

The description parameter is simply passed through to the description element of the member dictionary. It is intended to be used for explanations of the meaning of the member beyond that provided by the name.

### Formattters

All members may have a formatter parameter which is a function used to format the extracted value. 
This function should accept a parameter which is the extracted value and should return a new value.
The original value exists in the member as "value" and he formatted value is stored under the kwy formatted_value.
When a formatter isn't specified, the value is also typically provided as formatted_value except where value is a
collection of other members (ex. subfield is used).

Enstructured provides some simple formatters and factories for formatters. See Example 4 where a formatter is used transform a unix timestamp from a uint32 to a isoformat datetime string and an enum factory is used.

### Dynamic Parameters using eval()

To permit dynamic structure definitions, including specifications where members rely on values extracted previously, all parameters can be evaluated using the eval() capability.
To enable eval() of a parameter, it must be a string that starts and ends with ticks "`". The contents of the string (sans the outer ticks) are run through eval() and that paramter is set to the result of the evaluation.

See Example 3 where the value of a previous member is used to set the location of another member.

#### Variables available during parameter eval()
The following variables are available during parameter evaluation:

- members: the current members dictionary
- parent_members: a list of the members for the current extractor's lineage. parent_members[0] is the parent's members. parent_members[1] is the grandparent. This is only applicable for subfield extractors.
- params: dictionary of parameters provided for the current member
- current_location: location of the Extractor object in processing the buffer. I.e. location + length of the previous member.
- base_location: location of beginning of structure
- current_offset: location of the Extractor object in processing the structure. current_location = base_location + current_offset
- external_data: data provided to the Extractor though the external data parameter. By convention this data is a dictionary permitting multiple data items to be provided.
- data: the input data buffer






