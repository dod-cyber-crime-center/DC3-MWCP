import re
import logging
from mwcp import Parser, metadata
import pdb
import subprocess
import os

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class SSHPublicKey(Parser):
    DESCRIPTION = "SSHPublicKey Parser"
    AUTHOR = "fh"

    @classmethod
    def identify(cls, file_object):
        return True

    def run(self):
        regex=r'((?:ssh|ecdsa)[^\s]+)\s+([^\s]+)(?:\s+([^\n]+))?\n'
        logger.info(f"{self.DESCRIPTION} by {self.AUTHOR}")
        file_content = self.file_object.data.decode(errors="backslashreplace")
        matches = re.findall(regex, file_content, re.IGNORECASE)
        for m in matches:
            self.report.add(metadata.Other('ssh_public_key',m[1]))
            self.report.add(metadata.Other('ssh_public_key_type',m[0]))
            self.report.add(metadata.Other('ssh_public_key_user',m[2]))


class SSHPrivateKey(Parser):
    DESCRIPTION = "SSH Private Key Parser"
    AUTHOR = "fh"    

    @classmethod
    def identify(cls, file_object):
        return True

    def isencrypted(self,data):
        tmp_file = open('/tmp/temp.file','w')
        tmp_file.write(data)
        tmp_file.flush()
        tmp_file.close()
        os.chmod('/tmp/temp.file',0o600)

        result = subprocess.run(['ssh-keygen','-f','/tmp/temp.file', '-y','-P', ''],
            capture_output=True, text=True
        )
        if len(result.stdout) > 0:
            return False,result.stdout
        else:
            return True,""

    def run(self):
        regex=r'(\-{5}BEGIN\x20[^\x20]+\x20PRIVATE\x20KEY\-{5}\n.*?\-{5}END\x20[^\x20]+\x20PRIVATE\x20KEY\-{5})'
        logger.info(f"{self.DESCRIPTION} by {self.AUTHOR}")
        file_content = self.file_object.data.decode(errors="backslashreplace")
        matches = re.findall(regex, file_content, re.DOTALL)
        test_is_encrypted = self.isencrypted(file_content)
        for m in matches:
            if test_is_encrypted[0]:
                self.report.add(metadata.Other("Encrypted_SSH_Private_Key",m))
            else:
                self.report.add(metadata.Other("Unencrypted_SSH_Private_Key",m))
                self.report.add(metadata.Other("Associated_Public_Key",test_is_encrypted[1]))
