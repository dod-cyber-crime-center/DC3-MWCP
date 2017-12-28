#!/usr/bin/env python
'''
Example of using enstructured on pe header
'''
import enstructured
import pprint
import sys


PE_machines_enum_values = { 
    0x014c: "Intel 386",
    0x014d: "Intel 486",
    0x014e: "Intel 586",
    0x0200: "Intel 64-bit",
    0x0162: "MIPS",
    0x8664: "AMD64",
}    

NT_OPTIONAL_HEADER32 = [
    [enstructured.WORD,         "Magic",                {"formatter": enstructured.format_hex_int}],
    [enstructured.DWORD,        "LoaderFlags",          {"offset": 216, "formatter": enstructured.format_hex_int}],
    [enstructured.DWORD,        "NumberOfRvaAndSizes",  ],
]

NT_OPTIONAL_HEADER64 = [
    [enstructured.WORD,         "Magic",                {"formatter": enstructured.format_hex_int}],
    [enstructured.DWORD,        "LoaderFlags",          {"offset": 232, "formatter": enstructured.format_hex_int}],
    [enstructured.DWORD,        "NumberOfRvaAndSizes",  ],
]
   
subfield_map_NT_OPTIONAL_HEADER = {
    224 : NT_OPTIONAL_HEADER32,
    240 : NT_OPTIONAL_HEADER64,
}    

#Example 1: Use of structure definitions
IMAGE_SECTION_HEADER = [
    [enstructured.STR,          "Name",                     {"length": 0x8}],
    [enstructured.DWORD,        "VirtualSize",              ],
    [enstructured.DWORD,        "VirtualAddress",           ],
    [enstructured.DWORD,        "SizeOfRawData",            ],
    [enstructured.DWORD,        "PointerToRawData",         ],
    [enstructured.DWORD,        "PointerToRelocations",     ],
    [enstructured.DWORD,        "PointerToLinenumbers",     ],
    [enstructured.WORD,         "NumberOfRelocations",      ],
    [enstructured.WORD,         "NumberOfLinenumbers",      ],
    [enstructured.DWORD,        "Characteristics",          ],
]

PE_HEADER = [ 
    #Example 2: Use of item parameters
    [enstructured.STR,          "e_magic",                  {"length": 0x2, "description": "MZ header"}],
    [enstructured.DWORD,        "e_lfanew",                 {"offset": 0x3c, "formatter": enstructured.format_hex_int}],
    #Example 3: Use of tick based eval() 
    [enstructured.BYTES,          "Signature",              {"length": 0x4, "offset": '`members["e_lfanew"]["value"]`', "formatter": enstructured.format_hex}],
    #Example 4: Use of formatters
    [enstructured.WORD,         "Machine",                  {"formatter": enstructured.format_enum_factory(PE_machines_enum_values)}],
    [enstructured.WORD,         "NumberOfSections",         ],
    [enstructured.DWORD,        "TimeDateStamp",            {"formatter": enstructured.format_timestamp}],
    [enstructured.WORD,         "SizeOfOptionalHeader",     {"skip": 8}],
    #Example 5: Use of mapped subfield
    [enstructured.MAPSUBFIELD,  "IMAGE_OPTIONAL_HEADER",    {"skip": 2, "key": '`members["SizeOfOptionalHeader"]["value"]`', 
                                                            "specmap": subfield_map_NT_OPTIONAL_HEADER}],
    #Example 6: Use of list of subfieds
    [enstructured.SUBFIELDLIST, "sections",                 {"count": "`members[\"NumberOfSections\"][\"value\"]`", 
                                                            "spec": IMAGE_SECTION_HEADER, 
                                                            "offset": '`members["Signature"]["offset"] + members["SizeOfOptionalHeader"]["value"] + 24`'}],
]
 


def main():
    with open(sys.argv[1], "rb") as f: 
        data = f.read(4096)

    #Example 7: Extractor use    
    members = enstructured.Extractor(data = data, specification = PE_HEADER).extract_members()
    
    #just print the parsed data
    #pprint.pprint(members)
    
    #Example 8: print formatted_values only (filter out location, index, length, etc and convert to sorted list)
    pprint.pprint(enstructured.filter_formatted_values(members))
    
    #HTML hexdump view
    #print(enstructured.html_hex(data, enstructured.fix_member_indexes(enstructured.flatten_members(members, depth = 2))))
    
if __name__ == '__main__':
    main()


















