"""
This module contains parsers for digital certificates and RSA certificates.
"""
import base64
import hashlib
import re
import string
from datetime import datetime

import pyasn1.codec.der.decoder as asn1_decoder
import pyasn1.codec.der.decoder as ber_decoder
import pyasn1_modules.rfc2437 as rfc2437
import pyasn1_modules.rfc2459 as rfc2459
from pyasn1.error import PyAsn1Error

from mwcp import Parser, metadata


class DigitalCertificate(Parser):
    DESCRIPTION = "Digital Certificate (PEM)"

    RSA_CERT_RE = re.compile(br"-----BEGIN CERTIFICATE-----(?P<data>[^-]*)-----END CERTIFICATE-----", re.DOTALL)
    OIDS = {
        "2.5.4.3": "CN",
        "2.5.4.4": "Surname",
        "2.5.4.6": "C",
        "2.5.4.8": "ST",
        "2.5.4.7": "L",
        "2.5.4.10": "O",
        "2.5.4.11": "OU",
        "2.5.4.12": "Title",
        "1.2.840.113549.1.9.1": "emailAddress"
    }

    @classmethod
    def identify(cls, file_object):
        return cls.RSA_CERT_RE.search(file_object.data) and all(
            c in string.printable.encode() for c in file_object.data
        )

    @staticmethod
    def _from_bits(bits):
        """
        Convert a bitstream to characters.

        :param bits: A bitstream.

        :return: Converted bitstream.
        """
        chars = bytearray()
        for b in range(len(bits) // 8):
            byte = bits[b * 8: (b + 1) * 8]
            chars.append((int("".join([str(bit) for bit in byte]), 2)))
        return bytes(chars)

    def _parse_rdn(self, rdn_list):
        """
        Given a rdn list, convert it to a readable string.

        :param rdn_list: The rdn data in list format
        :return: A readable string containing the rdn information
        """
        str_list = []
        for rdn in rdn_list:
            oid = str(rdn[0][0])
            value = rdn[0][1]
            str_list.append("{}={} ".format(self.OIDS.get(oid, oid), ber_decoder.decode(value)[0]))
        return ", ".join(str_list)

    def parse_rsa_cert(self, rsa_data: bytes):
        """
        Given an RSA certificate in DER format, parse it for reportable information.

        :param rsa_data: The RSA data in DER format
        :return:
        """
        self.logger.debug("The RSA Certificate is stored in ASN.1 DER format. Parsing for reportable metadata.")
        cert = asn1_decoder.decode(rsa_data, asn1Spec=rfc2459.Certificate())[0]
        tbs_cert = cert.getComponentByName("tbsCertificate")
        rsa_key_data = self._from_bits(
            tbs_cert.getComponentByName("subjectPublicKeyInfo").getComponentByName("subjectPublicKey"))
        serial = tbs_cert.getComponentByName("serialNumber")
        issuer = self._parse_rdn(tbs_cert.getComponentByName("issuer")[0])
        subject = self._parse_rdn(tbs_cert.getComponentByName("subject")[0])
        valid_from = tbs_cert.getComponentByName("validity").getComponentByName("notBefore").getComponentByName(
            "utcTime")
        valid_from_str = datetime.strptime(str(valid_from), "%y%m%d%H%M%SZ").strftime("%Y-%m-%d %H:%M:%S")
        valid_to = tbs_cert.getComponentByName("validity").getComponentByName("notAfter").getComponentByName("utcTime")
        valid_to_str = datetime.strptime(str(valid_to), "%y%m%d%H%M%SZ").strftime("%Y-%m-%d %H:%M:%S")

        info_dict = {"rsa_cert_serial": "0x{:x}".format(int(serial)),
                     "rsa_cert_issuer": "{}".format(issuer),
                     "rsa_cert_subject": subject,
                     "rsa_cert_valid_from": "{}".format(valid_from_str),
                     "rsa_cert_valid_to": "{}".format(valid_to_str),
                     "rsa_cert_modulus": None,
                     "rsa_pub_exponent": None,
                     "rsa_cert_sha1": None}
        # If we fail to extract Public Key, don"t fail the entire thing.
        try:
            rsa_info = asn1_decoder.decode(rsa_key_data, asn1Spec=rfc2437.RSAPublicKey())[0]
            info_dict["rsa_cert_modulus"] = int(rsa_info.getComponentByName("modulus"))
            info_dict["rsa_pub_exponent"] = int(rsa_info.getComponentByName("publicExponent"))
            info_dict["rsa_cert_sha1"] = hashlib.sha1(rsa_data).hexdigest()
        except PyAsn1Error:
            self.logger.debug("Failed to extract RSAPublicKey", exc_info=1)

        return info_dict

    def run(self):
        # Extract and report certificate information.
        for cert in self.RSA_CERT_RE.finditer(self.file_object.data):
            cert_pem = cert.group("data")
            cert_der = base64.b64decode(cert_pem)
            if cert_der:
                cert_info = self.parse_rsa_cert(cert_der)

                pub_exponent = cert_info.pop("rsa_pub_exponent")
                modulus = cert_info.pop("rsa_cert_modulus")
                if pub_exponent or modulus:
                    self.report.add(metadata.RSAPublicKey(public_exponent=pub_exponent, modulus=modulus))

                ssl_cert_sha1 = cert_info.pop("rsa_cert_sha1")
                if ssl_cert_sha1:
                    self.report.add(metadata.SSLCertSHA1(ssl_cert_sha1))

                # TODO: Add a proper SSLCert metadata element.
                for key, value in cert_info.items():
                    self.report.add(metadata.Other(key, value))


class PrivateKey(Parser):
    DESCRIPTION = "RSA Private Key"

    RSA_PRIV_KEY_RE = re.compile(
        br"-----BEGIN RSA PRIVATE KEY-----(?P<data>[^-]*)-----END RSA PRIVATE KEY-----",
        re.DOTALL
    )

    @classmethod
    def identify(cls, file_object):
        return cls.RSA_PRIV_KEY_RE.search(file_object.data) and all(
            c in string.printable.encode() for c in file_object.data
        )

    def run(self):
        for match in self.RSA_PRIV_KEY_RE.finditer(self.file_object.data):
            self.report.add(metadata.RSAPrivateKey.from_PEM(match.group(0).decode()))
