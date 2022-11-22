"""
Visual Basic
"""

import pathlib
import string

from mwcp import Parser, FileObject


def istext(s, threshold=0.30):
    """
    Check if input string s is ASCII text.
    www.safaribooksonline.com/library/view/python-cookbook-2nd/0596007973/ch01s12.html

    :param s: input string
    :param threshold: percentage of characters allowed to have the high bit set (0 - 1)

    :return: bool
    """
    text_characters = string.printable.encode()
    null_trans = bytes.maketrans(b"", b"")
    if not s or b"\0" in s:
        return False

    # Get the substring of s made up of non-text characters
    t = s.translate(null_trans, text_characters)
    # s is 'text' if less than "threshold" of its characters are non-text
    return (len(t) / len(s)) <= threshold


class VBScript(Parser):
    """
    Identifies a VBS script.
    """
    DESCRIPTION = "VBScript"

    VB_KEYWORDS = [b"dim ", b"sub ", b"end sub", b"end function", b"createobject("]

    @classmethod
    def identify(cls, file_object):
        """
        Identify VB code based on the existence of specific VBS keywords.

        :param file_object: dispatcher.FileObject object

        :return: bool
        """
        lower_cased = file_object.data.lower()
        return istext(lower_cased) and any(keyword in lower_cased for keyword in cls.VB_KEYWORDS)


class VBE(Parser):
    """
    Finds and extracts VBE encoded VBSscript from file.
    """
    DESCRIPTION = "Encoded VBScript"

    START_TAG = b"#@~^"
    END_TAG = b"==^#~@"

    WHICH = "1231232332321323132311233213233211323231311231321323112331123132"

    @classmethod
    def identify(cls, file_object):
        """
        Check file magic to validate file contains a VBE
        (not just checking first bytes because we could be an ASP file)

        :param dispatcher.FileObject file_object: Input file

        :return bool: If parameters are met
        """
        return (
            cls.START_TAG in file_object.data
            and cls.END_TAG in file_object.data
            # Start tag should be found somewhere in the beginning of file.
            # May not be immediately in the beginning if script is in an ASP.
            and file_object.data.index(cls.START_TAG) in range(60)
        )

    def _generate_alphabet(self):
        alphabets = [chr(i) * 3 for i in range(128)]
        alphabets[32:128] = [
            '.-2', 'Gu0', 'zR!', 'V`)', 'Bq[', 'j^8', '/I3', '&\\=', 'IbX', 'A}:', '4)5', '26e',
            '[ 9', 'v|\\', 'rzV', 'C\x7fs', '8kf', '9cN', 'p3E', 'E+k', 'hhb', 'qQY', 'Ofx',
            '\tv^', 'b1}', 'DdJ', '#Tm', 'uCq', '<<<', '~:`', '>>>', '^~S', '@@@', 'wEB', 'J,\'',
            'a*H', ']tr', '"\'u', 'K71', 'oD7', 'NyM', ';YR', 'L/"', 'PoT', 'g&j', '*rG', '}jd',
            't9-', 'T{ ', '+?\x7f', '-8.', ',wL', '0g]', 'nS~', 'kGl', 'f4o', '5xy', '%]t', '!0C',
            'd#&', 'MZv', 'R[%', 'cl$', '?H+', '{U(', 'xp#', ')iA', '(.4', 'sL\t', 'Y!*', '3$D',
            '\x7fN?', 'mPw', 'U\t;', 'SVU', '|si', ':5a', '_ac', 'eKP', 'FXg', 'X;Q', '1WI',
            'i"O', 'lmF', 'ZMh', 'H%|', '\'(6', '\\Fp', '=Jn', '$2z', 'yA/', '7=_', '`_K', 'QOZ',
            ' B,', '6eW'
        ]
        alphabets[9] = 'Wn{'
        return alphabets

    def decode_vbe(self) -> str:
        """
        Decodes and returns embedded VBE script.
        """
        data = self.file_object.data

        # Extract vbe code part.
        start = data.index(self.START_TAG) + len(self.START_TAG) + 8
        end = data.index(self.END_TAG) - 6
        enc_code = data[start:end].decode("utf-8")

        # Perform replacements.
        enc_code = enc_code.replace('@&', '\x0a')
        enc_code = enc_code.replace('@#', '\x0d')
        enc_code = enc_code.replace('@*', '>')
        enc_code = enc_code.replace('@!', '<')
        enc_code = enc_code.replace('@$', '@')

        # Create the replacement alphabets and decode the script
        dec_code = []
        alphabets = self._generate_alphabet()
        for i, vbe_datum in enumerate(enc_code):
            vbe_datum_ord = ord(vbe_datum)
            if vbe_datum_ord < 128:
                dec_code.append(alphabets[vbe_datum_ord][int(self.WHICH[i % 64]) - 1])
            else:
                dec_code.append(vbe_datum)
        dec_code = "".join(dec_code)

        return dec_code

    def run(self):
        vbe = self.decode_vbe()
        dec_data = vbe.encode("utf8")
        # Base filename off original if entire file is encoded piece.
        if self.file_object.data.startswith(self.START_TAG):
            stem = pathlib.Path(self.file_object.name).stem
            self.dispatcher.add(FileObject(dec_data, file_name=f"{stem}.vb"))
        else:
            self.dispatcher.add(FileObject(dec_data, ext=".vb"))


class EncodedASP(VBE):
    """
    Identifies ASP file with VBE.
    """
    DESCRIPTION = "ASP with Encoded VBScript"

    START_TAG = b"<%" + VBE.START_TAG
