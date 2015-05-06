#!/usr/bin/env python
'''
DC3-MWCP client tool--submit files to the mwcp-server
'''

import os
import sys
import httplib
import uuid
import optparse
import urllib2
import json
import base64

def make_opt_parser():
    '''
    create a option parser to handle command line inputs
    '''
    
    usage_str = 'usage:  %s [options] FILE' % (os.path.basename(sys.argv[0]))
    description = "DC3-MWCP Framework: client utility for REST API"
    opt_parser = optparse.OptionParser(usage_str, description = description)

    opt_parser.add_option('-l',
                          '--list',
                          action = "store_true",
                          default = False,
                          dest = 'list',
                          help = 'list all malware config parsers')
    opt_parser.add_option('-p',
                          '--parser',
                          action ='store',
                          type = 'string',
                          default = None,
                          dest = 'parser',
                          help = 'malware config parser to call')
    opt_parser.add_option('-H',
                          '--host',
                          action = 'store',
                          type = 'string',
                          metavar = 'HOST',
                          default = "localhost:8080",
                          dest = 'host',
                          help = 'mwcp-server host' + " [default: %default]")
    opt_parser.add_option('-w',
                          '--kwargs',
                          action = 'store',
                          type = 'string',
                          metavar = 'JSON',
                          default = '',
                          dest = 'kwargs_raw',
                          help = 'module keyword arguments as json encoded dictionary\
                          if values in the dictionary use the special paradigm b64file(filename), then \
                          filename is read, base64 encoded, and used as the value')

    return opt_parser

def main():
    
    optparser = make_opt_parser()
    options, args = optparser.parse_args()
    
    if options.list:
        url = "http://%s/descriptions" % (options.host)
        response = urllib2.urlopen(url)
        print(response.read())
        sys.exit(0)
    
    if len(args) < 1 or not options.parser:
        optparser.print_help()
        sys.exit(1)
    
    filename = args[0]
    
    modargs = ""
    kwargs = {}
    if options.kwargs_raw: 
        kwargs = dict(json.loads(options.kwargs_raw))
        for key, value in kwargs.iteritems():
            if value and len(value) > len("b64file("):
                if value[:len("b64file(")] == "b64file(" and value[-1] == ")":
                    tmp_filename = value[len("b64file("):-1]
                    with open(tmp_filename, "rb") as f:
                        kwargs[key] = base64.b64encode(f.read())
        modargs = json.dumps(kwargs)
        
    
    responsedata = post_file(options.host, "/run_parser/" + options.parser, filename, modargs = modargs)
    responseobject = json.loads(responsedata)
    
    if "outputfile" in responseobject:
        newoutputfile = []
        #outputfile is overloaded with base64 encoded file data.
        #remove file data from metadata and write to filesystem
        for file_entry in responseobject["outputfile"]:
            if len(file_entry) == 3:
                with open(file_entry[0], "wb") as f:
                    f.write(base64.b64decode(file_entry[2]))
            newoutputfile.append([file_entry[0], file_entry[1]])
        responseobject['outputfile'] = newoutputfile
        
    print json.dumps(responseobject)
   
def post_file(host, resource, filename, modargs = ""):
    base_boundary = '--------mwcp-client-----%s---------' % (uuid.uuid4())
    content_type = 'multipart/form-data; boundary=%s' % (base_boundary)
    body = encode_multipart(filename, base_boundary, modargs = modargs)
    headers = { "Content-Type": content_type, "Content-Length": str(len(body)) }
    conn = httplib.HTTPConnection(host)
    conn.request('POST', resource, body, headers)
    response = conn.getresponse()
    return response.read()
    
def encode_multipart(filename, base_boundary, modargs = ""):
    with open(filename, 'rb') as f:
        data = f.read()
    body = []
    if modargs:
        body.extend(['--', base_boundary, '\r\n'])
        body.extend(['Content-Disposition: form-data; name="modargs"', '\r\n', '\r\n'])
        body.extend([modargs, '\r\n'])
    body.extend(['--', base_boundary, '\r\n'])
    body.extend(['Content-Disposition: form-data; name="data"; filename="%s"' % (filename), '\r\n'])
    body.extend(['Content-Type: application/octet-stream', '\r\n', '\r\n'])
    body.extend([data, '\r\n'])
    body.extend(['--', base_boundary, '--', '\r\n', '\r\n'])
    return ''.join(body)
    
if __name__ == '__main__':
    main()    
