
import re
from typing import List

from mwcp import Parser, metadata


class Script(Parser):
    """
    Generic parser for pulling suspect URLs from a Powershell script
    """
    DESCRIPTION = "PowerShell Script"
    AUTHOR = "DC3"

    INVALID_DOMAINS = [
        "ipify.org",
        "whatismyipaddress.com"
    ]

    URL_REGEX = re.compile(
        (
            # HTTP/HTTPS.
            b"(https?://)"
            b"((["
            # IP address.
            b"(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\."
            b"(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\."
            b"(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\."
            b"(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])]|"
            # Or domain name.
            b"[a-zA-Z0-9.-]+)"
            # Optional port.
            b"(:\\d+)?"
            # URI.
            b"(/[()a-zA-Z0-9_:%=/.-]*)?"
        )
    )

    @classmethod
    def identify(cls, file_object):
        return file_object.name.endswith(".ps1")

    def extract_urls(self, data: bytes) -> List[str]:
        """
        Extract URLs using regular expression.

        :param data: Data to search for URLs in
        :return: List of extracted URLs (with duplicates removed)
        :rtype: list[str]
        """
        urls = set()
        for match in self.URL_REGEX.finditer(data):
            url = match.group().decode()
            if not any(invalid in url for invalid in self.INVALID_DOMAINS):
                urls.add(url)
        return list(urls)

    def run(self):
        """
        Presently only search for extract-able URLs.
        """
        # General report of URLS.
        urls = self.extract_urls(self.file_object.data)
        for url in urls:
            self.report.add(metadata.URL(url))
