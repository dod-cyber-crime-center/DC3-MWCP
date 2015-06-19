#!/usr/bin/env python
'''
DC3-MWCP cli tool--makes available functionality of DC3-MWCP framework
'''

import os
import sys
import optparse
import traceback
import hashlib
import datetime
import tempfile
import json
import base64
from mwcp.malwareconfigreporter import malwareconfigreporter


def make_opt_parser():
    '''
    create a option parser to handle command line inputs
    '''
    usage_str = 'usage:  %s [options] FILES' % (os.path.basename(sys.argv[0]))
    description = "DC3-MWCP Framework: utility for executing parser modules"
    opt_parser = optparse.OptionParser(usage_str, description = description)

    #available opts:    
    #--c-e-----------q-s--v-xyz
    #A-Z

    
    default_parserdir = ''
    default_resourcedir = ''
    
    #create reporter to get default paths, ignore if this fails
    try:
        default_reporter = malwareconfigreporter()
        default_parserdir = default_reporter.parserdir 
        default_resourcedir = default_reporter.resourcedir
    except Exception as e:
        pass
    
    opt_parser.add_option('-p',
                          '--parser',
                          action = 'store',
                          type = 'string',
                          default = '',
                          dest = 'parser',
                          help = 'malware config parser to call')
    opt_parser.add_option('-l',
                          '--list',
                          action = "store_true",
                          default = False,
                          dest = 'list',
                          help = 'list all malware config parsers')
    opt_parser.add_option('-k',
                          '--listfields',
                          action = "store_true",
                          default = False,
                          dest = 'fields',
                          help = 'list all standardized fields and examples. See resources/fields.json')
    opt_parser.add_option('-a',
                          '--parserdir',
                          action = 'store',
                          type = 'string',
                          metavar = 'DIR',
                          default = default_parserdir,
                          dest = 'parserdir',
                          help = 'parsers directory' + ' [default: %default]')
    opt_parser.add_option('-r',
                          '--resourcedir',
                          action = 'store',
                          type = 'string',
                          metavar = 'DIR',
                          default = default_resourcedir,
                          dest = 'resourcedir',
                          help = 'resources directory' + ' [default: %default]')
    opt_parser.add_option('-o',
                          '--outputdir',
                          action = 'store',
                          type = 'string',
                          metavar = 'DIR',
                          default = '',
                          dest = 'outputdir',
                          help = 'output directory' + ' [default: %default]')
    opt_parser.add_option('-t',
                          '--tempdir',
                          action = 'store',
                          type = 'string',
                          metavar = 'DIR',
                          default = tempfile.gettempdir(),
                          dest = 'tempdir',
                          help = 'temp directory' + ' [default: %default]')
    opt_parser.add_option('-j',
                          '--jsonoutput',
                          action = 'store_true',
                          default = False,
                          dest = 'jsonoutput',
                          help = 'Enable json output for parser reports (instead of formatted text)')
    opt_parser.add_option('-n',
                          '--disableoutputfiles',
                          action = "store_true",
                          default = False,
                          dest = 'disableoutputfiles',
                          help = 'disable writing output files to filesystem')
    opt_parser.add_option('-g',
                          '--disabletempcleanup',
                          action = 'store_true',
                          default = False,
                          dest = 'disabletempcleanup',
                          help = 'Disable cleanup of framework created temp files including managed tempdir')
    opt_parser.add_option('-f',
                          '--includefileinfo',
                          action = 'store_true',
                          default = False,
                          dest = 'includefilename',
                          help = 'include input file information such as filename, hashes, and compile time in parser output')
    opt_parser.add_option('-d',
                          '--hidedebug',
                          action = "store_true",
                          default = False,
                          dest = 'hidedebug',
                          help = 'Hide debug messages in output')
    opt_parser.add_option('-u',
                          '--outputfileprefix',
                          action = 'store',
                          type = 'string',
                          metavar = 'FILENAME',
                          default = '',
                          dest = 'outputfile_prefix',
                          help = 'string prepended to output files written to filesystem. specifying "md5"\
                          will cause output files to be prefixed with the md5 of the input file' + ' [default: %default]')
    opt_parser.add_option('-i',
                          '--filelistindirection',
                          action = "store_true",
                          default = False,
                          dest = 'filelistindirection',
                          help = 'input file contains a list of filenames to process')
    opt_parser.add_option('-b',
                          '--base64outputfiles',
                          action = "store_true",
                          default = False,
                          dest = 'base64outputfiles',
                          help = 'base64 encode output files and include in metadata')
    opt_parser.add_option('-w',
                          '--kwargs',
                          action = 'store',
                          type = 'string',
                          metavar = 'JSON',
                          default = '',
                          dest = 'kwargs_raw',
                          help = 'module keyword arguments as json encoded dictionary\
                          if values in the dictionary use the special paradigm "b64file(filename)", then \
                          filename is read, base64 encoded, and used as the value')
    return opt_parser

def main():

    
    
    optparser = make_opt_parser()
    options, args = optparser.parse_args()

    #if we can not create reporter object there is very little we can do. Just die immediately.
    try:
        reporter = malwareconfigreporter(parserdir = options.parserdir,
                                        resourcedir = options.resourcedir,
                                        outputdir = options.outputdir,
                                        outputfile_prefix = options.outputfile_prefix,
                                        tempdir = options.tempdir,
                                        disabledebug = options.hidedebug,
                                        disableoutputfiles = options.disableoutputfiles,
                                        disabletempcleanup = options.disabletempcleanup,
                                        base64outputfiles = options.base64outputfiles)
    except Exception as e:
        error_message = "Error loading DC3-MWCP reporter object, please check installation: %s" % (traceback.format_exc())
        if options.jsonoutput:
            print('{"errors": ["%s"]}' % (error_message))
        else:
            print(error_message)
        sys.exit(1)
    
    if options.list:
        descriptions = reporter.get_parser_descriptions()

        if options.jsonoutput:
            if reporter.errors:
                descriptions.append({"errors": reporter.errors})
            print reporter.pprint(descriptions)
        else:
            for name, author, description in sorted(descriptions):
                print('%-25s %-8s %s' % (name, author, description) )
            if reporter.errors:
                print("")
                print("Errors:")
                for error in reporter.errors:
                    print("    %s" % (error))
        return
    
    if options.fields:
        if options.jsonoutput:
            print reporter.pprint(reporter.fields)
        else:
            for key in sorted(reporter.fields):
                print('%-20s %s' % (key, reporter.fields[key]['description']))
                for example in reporter.fields[key]['examples']:
                    print('%s %s' % (" " * 24, json.dumps(example)))     
        return
    
    if not args:
        optparser.print_help()
        return
        
    if options.parser:
        if options.filelistindirection:
            if args[0] == "-":
                inputfilelist = [ line.rstrip() for line in sys.stdin ]
            else:
                with open(args[0],"rb") as f:
                    inputfilelist = [ line.rstrip() for line in f ]
        else:
            inputfilelist = args
        
        kwargs = {}
        if options.kwargs_raw: 
            kwargs = dict(json.loads(options.kwargs_raw))
            for key, value in kwargs.iteritems():
                if value and len(value) > len("b64file("):
                    if value[:len("b64file(")] == "b64file(" and value[-1:] == ")":
                        tmp_filename = value[len("b64file("):-1]
                        with open(tmp_filename, "rb") as f:
                            kwargs[key] = base64.b64encode(f.read())
        
        for inputfilename in inputfilelist:
            if inputfilename == "-":
                reporter.run_parser(options.parser, data=sys.stdin.read(), **kwargs)
            else:
                reporter.run_parser(options.parser, inputfilename, **kwargs)
            
            if options.includefilename:
                reporter.metadata['inputfilename'] = inputfilename
                reporter.metadata['md5'] = hashlib.md5(reporter.data).hexdigest()
                reporter.metadata['sha1'] = hashlib.sha1(reporter.data).hexdigest()
                reporter.metadata['sha256'] = hashlib.sha256(reporter.data).hexdigest()
                reporter.metadata['parser'] = options.parser    
                if reporter.pe:
                    reporter.metadata['compiletime'] = datetime.datetime.fromtimestamp(reporter.pe.FILE_HEADER.TimeDateStamp).isoformat()
        
            if options.jsonoutput:
                output = reporter.metadata
                if reporter.errors:
                    output["errors"] = reporter.errors
                print reporter.pprint(output)
            else:
                reporter.output_text()
    
if __name__ == '__main__':
    main()
