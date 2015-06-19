#!/usr/bin/env python
'''
technanarchy_bridge -- library to execute techanarchy ratdecoders and parse output for DC3-MWCP framework
'''

import os
import sys
import subprocess
import re
import cStringIO

# Allowing for two tabs to accommodate Punisher
TECHANARCHY_OUTPUT_RE = r'''Key: (.*?)\t{1,2} Value: (.*)'''
TECHANARCHY_DIRECTORY = 'RATDecoders'

def map_bozok_domains(data, reporter):
    domainlist = data['Domain'].split('*')
    for domain in domainlist:
        if len(domain) > 0:
            if 'Port' in data:
                reporter.add_metadata('c2_socketaddress', [domain, data['Port'], 'tcp'])
            else:
                reporter.add_metadata('c2_address', domain)

def map_unrecom_jar_info(data, reporter):
    jarinfo = ''
    mwcpkey = ''
    if 'jarfoldername' in data:
        jarinfo = data['jarfoldername']
        mwcpkey = 'directory'
    if 'jarname' in data:
        # if a directory is added put in the \\
        if len(jarinfo) > 0:
            jarinfo += '\\'
        if 'extensionname' in data:
            jarinfo += data['jarname'] + '.' + data['extensionname']
            if mwcpkey == 'directory':
                mwcpkey = 'filepath'
            else:
                mwcpkey = 'filename'
        else:
            if mwcpkey == 'directory':
                mwcpkey = 'filepath'
            else:
                mwcpkey = 'filename'
            jarinfo += data['jarname']
    reporter.add_metadata(mwcpkey, jarinfo)

def map_domainX_fields(data, reporter):
    suffix_list = ['1',  '2',  '3',  '4',  '5',  '6',  '7',  '8',  '9',  '10',
                   '11', '12', '13', '14', '15', '16', '17', '18', '19', '20']
    special_handling_list = ['Domain1', 'Domain2']
    for suffix in suffix_list:
        field = 'Domain' + suffix
        if field in data:
            if not(data[field] == ':0'):
                if ':' in data[field]:
                    address, port = data[field].split(':')
                    reporter.add_metadata('c2_socketaddress', [address, port, 'tcp'])
                else:
                    if field in special_handling_list:
                        if field in data:
                            if "Port" in data:
                                reporter.add_metadata("c2_socketaddress", [data[field], data['Port'], "tcp"])
                            elif ("Port" + suffix) in data:
                                #assume tcp and c2--use per scriptname customization if this doesn't hold
                                reporter.add_metadata("c2_socketaddress", [data[field], data['Port' + suffix], "tcp"])
                            else:
                                reporter.add_metadata("c2_address", data[field])
                        elif "Port" + suffix in data:
                            reporter.add_metadata("port", [data['Port' + suffix], "tcp"])
                    else:
                        if field in data:
                            if not(data[field] == ':0'):
                                if ':' in data[field]:
                                    address,port = data[field].split(':')
                                    reporter.add_metadata('c2_socketaddress', [address, port, 'tcp'])
                                else:
                                    reporter.add_metadata('c2_address', data[field])


def run_decoder(reporter, script, scriptname=""):
    '''
    Run a RATdecoder and report output

    reporter: mwcp reporter object
    script: path of script to execute
    scriptname: This is the name of the decoder script, which is used for decoder specific logic. This is defaults to the basename of the script with the .py removed

    '''
    if not scriptname:
        scriptname = os.path.basename(script)[:-3]

    tempdir = reporter.managed_tempdir()
    outputfile = os.path.join(tempdir, "techanarchy_output")

    if reporter.interpreter_path():
        command = [reporter.interpreter_path(), script, reporter.filename(), outputfile]
    else:
        command = [script, reporter.filename(), outputfile]

    reporter.debug("Running %s using %s" % (scriptname, " ".join(command)))

    pipe = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    stdout, stderr = pipe.communicate(None)

    termhandle = cStringIO.StringIO(stdout)
    for line in termhandle:
        reporter.debug(line.rstrip())

    termhandle = cStringIO.StringIO(stderr)
    for line in termhandle:
        reporter.debug(line.rstrip())

    if pipe.returncode != 0:
        reporter.debug("Error running script. Return code: %i" % ( pipe.returncode))

    configlist = []
    try:
        with open(outputfile, "rb") as f:
            configlist = [ line.rstrip("\n\r") for line in f ]
    except Exception as e:
        reporter.debug("Error reading script output file: %s" % str(e))

    output_re = re.compile(TECHANARCHY_OUTPUT_RE)
    output_data = {}

    for item in configlist:
        match = output_re.search(item)
        if match:
            key = match.group(1)
            value = match.group(2)
            reporter.add_metadata("other",{key: value})
            if value:
                if key in output_data:
                    reporter.debug("collision on output key: %s" % key)
                output_data[key] = value
        else:
            reporter.debug("Could not parse output item: %s" % (item))



    data = output_data


    '''
    Updates to field mapping code belongs below here

    scriptname can be use to make per decoder customizations
    '''

    if "Domain" in data:
        if scriptname == 'Bozok':
            map_bozok_domains(data, reporter)
        else:
            if scriptname == 'Pandora':
                data['Domain'] = data['Domain'].strip('*')
            if "Port" in data:
                #assuming these are all TCP. If there are ever decoders for families that UDP, address here
                #also assuming these are all c2. If that pattern doesn't hold, then put in a conditional for decoders there Domain isn't a c2_domain
                if scriptname == "CyberGate":
                    reporter.add_metadata("c2_socketaddress", [data['Domain'].rstrip("|"), data['Port'].rstrip("|"), "tcp" ] )
                else:
                    reporter.add_metadata("c2_socketaddress", [data['Domain'], data['Port'], "tcp" ] )
            elif 'Port1' in data or 'Port2' in data:
                if 'Port1' in data:
                    reporter.add_metadata("c2_socketaddress", [data['Domain'], data['Port1'], "tcp" ] )
                if 'Port2' in data:
                    reporter.add_metadata("c2_socketaddress", [data['Domain'], data['Port2'], "tcp" ] )
            elif "Client Control Port" in data or "Client Transfer Port" in data:
                if "Client Control Port" in data:
                    reporter.add_metadata("c2_socketaddress", [data['Domain'], data['Client Control Port'], "tcp" ] )
                if "Client Transfer Port" in data:
                    reporter.add_metadata("c2_socketaddress", [data['Domain'], data['Client Transfer Port'], "tcp" ] )
            else:
                 if scriptname == "LuxNet":
                    if '\\' in data['Domain']:
                        reporter.add_metadata("registrypath", data['Domain'])
                    else:
                        reporter.add_metadata("c2_address", data['Domain'])
                 else:
                     reporter.add_metadata("c2_address", data['Domain'])

            if "Client Transfer Port" in data:
                   reporter.add_metadata("port", [data['Client Transfer Port'], "tcp"])
            if "Client Control Port" in data:
                   reporter.add_metadata("port", [data['Client Control Port'], "tcp"])

    map_domainX_fields(data, reporter)

    if "dns" in data:
        if scriptname == 'unrecom':
            if 'p1' in data:
                reporter.add_metadata("c2_socketaddress", [data['dns'], data['p1'], 'tcp'])
            if 'p2' in data:
                reporter.add_metadata("c2_socketaddress", [data['dns'], data['p2'], 'tcp'])
        else:
            reporter.add_metadata("c2_address", data['dns'])

    if "Domains" in data:
        #example of script specific parsing
        if scriptname == "DarkComet" or scriptname == "poisonivy":
            for addrport in data["Domains"].split("|"):
                if ":" in addrport:
                    addr, port = addrport.split(":")
                    if scriptname == 'poisonivy':
                        addr = addr.translate(None,'5')
                    if addr and port:
                        reporter.add_metadata("c2_socketaddress", [addr, port, "tcp"])

    if "EncryptionKey" in data:
        reporter.add_metadata("key", data["EncryptionKey"])


    if "FTP Address" in data:
        if "FTP Directory" in data and "FTP Port" in data :
            reporter.add_metadata("c2_url", "ftp://" + data['FTP Address'] + ":" + data['FTP Port'] + "/" + data['FTP Directory'] )
        elif "FTP Directory" in data:
            reporter.add_metadata("c2_url", "ftp://" + data['FTP Address'] + "/" + data['FTP Directory'] )
        elif "FTP Port" in data:
            reporter.add_metadata("c2_url", "ftp://" + data['FTP Address'] + ":" + data['FTP Port'] )
        else:
            reporter.add_metadata("c2_url", "ftp://" + data['FTP Address'] )

    if "FTP Server" in data:
        if "FTP Folder" in data:
            reporter.add_metadata("c2_url", "ftp://" + data['FTP Server'] + "/" + data['FTP Folder'] )
        else:
            reporter.add_metadata("c2_url", "ftp://" + data['FTP Server']  )

    if "FTPHost" in data:
        if "FTPPort" in data:
            reporter.add_metadata("c2_url", "ftp://" + data['FTPHost'] + ":" + data['FTPPort'] )
        else:
            reporter.add_metadata("c2_url", "ftp://" + data['FTPHost']  )

    if "FTPHOST" in data:
        if "FTPPORT" in data:
            reporter.add_metadata("c2_url", "ftp://" + data['FTPHOST'] + ":" + data['FTPPORT'] )
        else:
            reporter.add_metadata("c2_url", "ftp://" + data['FTPPORT']  )

    if "Version" in data:
        reporter.add_metadata("version", data['Version'] )
    if "version" in data:
        reporter.add_metadata("version", data['version'] )

    if scriptname != 'jRat':
        if "Mutex" in data:
            reporter.add_metadata("mutex", data['Mutex'] )
    if "Mutex Main" in data:
        reporter.add_metadata("mutex", data['Mutex Main'] )
    if "Mutex 4" in data:
        reporter.add_metadata("mutex", data['Mutex 4'] )
    if "MUTEX" in data:
        reporter.add_metadata("mutex", data['MUTEX'] )
    if "mutex" in data:
        reporter.add_metadata("mutex", data['mutex'] )
    if "Mutex Grabber" in data:
        reporter.add_metadata("mutex", data['Mutex Grabber'] )
    if "Mutex Per" in data:
        reporter.add_metadata("mutex", data['Mutex Per'] )


    if "Password" in data:
        reporter.add_metadata("password", data['Password'])
    if "password" in data:
        reporter.add_metadata("password", data['password'])

    if "Campaign ID" in data:
        reporter.add_metadata("missionid", data['Campaign ID'])
    if "CampaignID" in data:
        reporter.add_metadata("missionid", data['CampaignID'])
    if "Campaign Name" in data:
        reporter.add_metadata("missionid", data['Campaign Name'])
    if "Campaign" in data:
        reporter.add_metadata("missionid", data['Campaign'])
    if "ID" in data:
        reporter.add_metadata("missionid", data['ID'])
    if "prefijo" in data:
        reporter.add_metadata("missionid", data['prefijo'])

    if "Process Injection" in data:
        reporter.add_metadata("injectionprocess", data['Process Injection'])
    if "Injection" in data:
        reporter.add_metadata("injectionprocess", data['Injection'])
    if "Inject Exe" in data:
        reporter.add_metadata("injectionprocess", data['Inject Exe'])

    if "Install Dir" in data:
        reporter.add_metadata("directory", data['Install Dir'])
    if "InstallDir" in data:
        reporter.add_metadata("directory", data['InstallDir'])
    if "Install Path" in data:
        reporter.add_metadata("directory", data['Install Path'])
    if "InstallPath" in data:
        reporter.add_metadata("directory", data['InstallPath'])
    if "Install Folder" in data:
        reporter.add_metadata("directory", data['Install Folder'])
    if "Install Folder1" in data:
        reporter.add_metadata("directory", data['Install Folder1'])
    if "Install Folder2" in data:
        reporter.add_metadata("directory", data['Install Folder2'])
    if "Install Folder3" in data:
        reporter.add_metadata("directory", data['Install Folder3'])
    if "Folder Name" in data:
        reporter.add_metadata("directory", data['Folder Name'])
    if "FolderName" in data:
        reporter.add_metadata("directory", data['FolderName'])
    if "pluginfoldername" in data:
        reporter.add_metadata("directory", data['pluginfoldername'])


    if "nombreCarpeta" in data:
        reporter.add_metadata("directory", data['nombreCarpeta'])

    if "Install Directory" in data:
        if "Install File Name" in data:
            #assume windows style path separators
            reporter.add_metadata("filepath", data["Install Directory"].rstrip("\\") + "\\" + data["Install File Name"])
        else:
            reporter.add_metadata("directory", data["Install Directory"])
    elif "Install File Name" in data:
        reporter.add_metadata("filename", data["Install File Name"])

    if "InstallName" in data:
       reporter.add_metadata("filename", data["InstallName"])
    if "Install Name" in data:
       reporter.add_metadata("filename", data["Install Name"])
    if "Exe Name" in data:
        reporter.add_metadata("filename", data["Exe Name"])
    if scriptname == 'unrecom':
        map_unrecom_jar_info(data, reporter)
    else:
        if "jarname" in data:
            reporter.add_metadata("filename", data["jarname"])
    if "JarName" in data:
        reporter.add_metadata("filename", data["JarName"])
    if "Jar Name" in data:
        reporter.add_metadata("filename", data["Jar Name"])
    if "StartUp Name" in data:
        if scriptname == 'VirusRat':
            reporter.add_metadata("filename", data["StartUp Name"])

    if scriptname == 'Bozok':
        if 'StartupName' in data:
            reporter.add_metadata("registrypath", data['StartupName'])

    if "File Name" in data:
        reporter.add_metadata("filename", data["File Name"])

    if "USB Name" in data:
        reporter.add_metadata("filename", data["USB Name"])

    if "Log File" in data:
        reporter.add_metadata("filename", data["Log File"])

    if "FTP UserName" in data:
        if "FTP Password" in data:
            reporter.add_metadata("credential", [ data['FTP UserName'], data['FTP Password'] ] )
        else:
            reporter.add_metadata("username", data['FTP UserName'])
    elif "FTP Password" in data:
        reporter.add_metadata("password", data['FTP Password'])

    if "FTPUserName" in data:
        if "FTPPassword" in data:
            reporter.add_metadata("credential", [ data['FTPUserName'], data['FTPPassword'] ] )
        else:
            reporter.add_metadata("username", data['FTPUserName'])
    elif "FTPPassword" in data:
        reporter.add_metadata("password", data['FTPPassword'])

    if "FTPUSER" in data:
        if "FTPPASS" in data:
            reporter.add_metadata("credential", [ data['FTPUSER'], data['FTPPASS'] ] )
        else:
            reporter.add_metadata("username", data['FTPUSER'])
    elif "FTPPASS" in data:
        reporter.add_metadata("password", data['FTPPASS'])
    if "Active X Key" in data:
        reporter.add_metadata("registrypath", data['Active X Key'])
    if "ActiveX Key" in data:
        reporter.add_metadata("registrypath", data['ActiveX Key'])
    if "Active X Startup" in data:
        reporter.add_metadata("registrypath", data['Active X Startup'])
    if "Registry Key" in data:
        reporter.add_metadata("registrypath", data['Registry Key'])
    if "Startup Key" in data:
        reporter.add_metadata("registrypath", data['Startup Key'])
    if "REG Key HKLM" in data:
        reporter.add_metadata("registrypath", data['REG Key HKLM'])
    if "HKLM Value" in data:
        if len(data["HKLM Value"]) > 0:
            reporter.add_metadata("registrypath", data['HKLM Value'])
    if "REG Key HKCU" in data:
        reporter.add_metadata("registrypath", data['REG Key HKCU'])
    if "Reg Key" in data:
        if "Reg Value" in data or 'Reg value' in data:
            if "Reg Value" in data:
                reporter.add_metadata("registrypath", (data['Reg Key'] + '\\' + data['Reg Value']))
            elif 'Reg value' in data:
                 reporter.add_metadata("registrypath", (data['Reg Key'] + '\\' + data['Reg value']))
        else:
            reporter.add_metadata("registrypath", data['Reg Key'])
    elif "Reg Value" in data or 'Reg value' in data:
        if "Reg Value" in data:
            reporter.add_metadata("registrypath", data['Reg Value'])
        elif 'Reg value' in data:
            reporter.add_metadata("registrypath", data['Reg value'])
    if "RegistryKey" in data:
        reporter.add_metadata("registrypath", data['RegistryKey'])
    if "RegKey1" in data:
        reporter.add_metadata("registrypath", data['RegKey1'])
    if "RegKey2" in data:
        reporter.add_metadata("registrypath", data['RegKey2'])
    if "HKCUKey" in data:
        reporter.add_metadata("registrypath", data['HKCUKey'])
    if "HKCU Key" in data:
        reporter.add_metadata("registrypath", data['HKCU Key'])
    if "Registry Value" in data:
        reporter.add_metadata("registrypath", data['Registry Value'])
    if "keyClase" in data:
        reporter.add_metadata("registrypath", data['keyClase'])
    if "regname" in data:
        reporter.add_metadata("registrypath", data['regname'])
    if "registryname" in data:
        reporter.add_metadata("registrypath", data['registryname'])
    if "Custom Reg Key" in data:
        reporter.add_metadata("registrypath", data['Custom Reg Key'])
    if "Custom Reg Name" in data:
        reporter.add_metadata("registrypath", data['Custom Reg Name'])
    if "Custom Reg Value" in data:
        reporter.add_metadata("registrypath", data['Custom Reg Value'])
    if "HKCU" in data:
        reporter.add_metadata("registrypath", data['HKCU'])
    if "HKLM" in data:
        reporter.add_metadata("registrypath", data['HKLM'])

    if "FTP Interval" in data:
        reporter.add_metadata("interval", data['FTP Interval'])

    if "RetryInterval" in data:
        reporter.add_metadata("interval", data['RetryInterval'])

    if "Screen Rec Link" in data:
        reporter.add_metadata("url", data['Screen Rec Link'])
    if "WebPanel" in data:
        reporter.add_metadata("url", data['WebPanel'])
    if "Plugins" in data:
        reporter.add_metadata("url", data['Plugins'])


def main():

    if len(sys.argv) < 2:
        print("usage: %s NAME ")
        print("NAME should should be decoder basename without .py extension.")
        print("when run as script, makes an DC3-MWCP parser for the specified malware")
        exit(1)

    scriptname = sys.argv[1]

    output = ""
    output += "import os\n"
    output += "from mwcp.malwareconfigparser import malwareconfigparser\n"
    output += "import techanarchy_bridge\n"
    output += "\n"
    output += "class TechAnarchy(malwareconfigparser):\n"
    output += "    def __init__(self,reporter=None):\n"
    output += "        malwareconfigparser.__init__(self,\n"
    output += "                description='Techanarchy %s RATdecoder using bridge',\n" % (scriptname)
    output += "                author='TA',\n"
    output += "                reporter=reporter\n"
    output += "                )\n"
    output += "\n"
    output += "    def run(self):\n"
    output += "        scriptpath = os.path.join(self.reporter.resourcedir, '%s', '%s' + '.py')\n" % (TECHANARCHY_DIRECTORY, scriptname)
    output += "        techanarchy_bridge.run_decoder(self.reporter, scriptpath)\n"
    output += "\n"

    with open(scriptname + "_TA_malwareconfigparser.py", "w") as f:
        f.write(output)

if __name__ == '__main__':
    main()
