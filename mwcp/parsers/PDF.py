"""
PDF
"""
import re

from mwcp import Parser, metadata


class Document(Parser):
    """
    Parses PDF file with some basic metadata extraction.
    """
    DESCRIPTION = "PDF Document"
    AUTHOR = "DC3"

    IGNORE_DOMAINS = [
        "www.w3.org",
        "ns.adobe.com",
        "purl.org",
    ]

    # 2-6 character protocol -> :// -> Up to 253 alphanumeric, "-", "_", or "." characters, (which should include all
    # valid domains or IP addresses) -> Nothing, or a port or "/" -> (For the port or "/") any non-whitespace characters.
    URL_RE = re.compile(
        b"[a-zA-Z]{2,6}"  # scheme
        b"://"
        b"([\w._\-]+(:[\w._\-]+)?@)?"  # user info
        b"[\w._\-]{4,253}"  # host
        b"(:[\d]{1,5})?"  # port
        b"(/[\w._\-~=%]*)*"  # path
        b"(\?[\w._\-~=&,%]+)?"  # query
        b"(#[\w._\-~]+)?"  # fragment
    )
    EMAIL_RE = re.compile(b"[\w.+-]+@([A-Za-z0-9](|[\w-]{0,61}[A-Za-z0-9])\.)+[A-Za-z]{2,6}")

    @classmethod
    def identify(cls, file_object):
        return file_object.data.startswith(b"%PDF") and (
            cls.URL_RE.search(file_object.data)
            or cls.EMAIL_RE.search(file_object.data)
        )

    def extract_urls(self):
        """
        Statically extract URLs embedded in the PDF.
        """
        for match in self.URL_RE.finditer(self.file_object.data):
            url = match.group()
            if not any(domain in url for domain in self.IGNORE_DOMAINS):
                self.report.add(metadata.URL(url))

    def extract_emails(self):
        """
        Statically extract URLs embedded in the PDF.
        """
        for match in self.EMAIL_RE.finditer(self.file_object.data):
            self.report.add(metadata.EmailAddress(match.group()))

    def run(self):
        self.extract_urls()
        self.extract_emails()
