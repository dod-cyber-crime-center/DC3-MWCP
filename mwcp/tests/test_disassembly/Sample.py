"""
Sample parser that uses dragodis disassembly library.
(This is a conversion from the kordesii "Sample" parser.)
"""

import dragodis
import rugosa

from mwcp import metadata, Parser


class Implant(Parser):
    DESCRIPTION = "Sample Implant"

    @classmethod
    def identify(cls, file_object):
        return file_object.md5 == "e1b6be6c0c2db8b3d4dca56062ca6301"

    @staticmethod
    def xor_decrypt(key, enc_data):
        return bytes((x ^ key) for x in enc_data)

    def find_strings(self, dis: dragodis.Disassembler):
        """
        Extracts and reports DecodedString objects for the parameters following xor encryption function:

            void encrypt(char *s, char key)
            {
                while (*s)
                    *s++ ^= key;
            }
        """
        emulator = rugosa.Emulator(dis)
        pattern = rugosa.re.compile(br"\x8b\x45\x08\x0f\xbe\x08")
        for encrypt_func in pattern.find_functions(dis):
            self.logger.info("Found XOR encrypt function at: 0x%x", encrypt_func.start)
            for call_ea in encrypt_func.calls_to:
                self.logger.debug("Tracing 0x%08x", call_ea)
                # Extract arguments for call to xor function.
                context = emulator.context_at(call_ea)
                enc_str_ptr, key = context.get_function_arg_values()

                enc_string_data = rugosa.get_terminated_bytes(dis, enc_str_ptr)
                dec_string_data = self.xor_decrypt(key, enc_string_data)
                string = rugosa.DecodedString(
                    dec_data=dec_string_data,
                    enc_data=enc_string_data,
                    # data is encrypted in-place, so include string pointer as decoded source.
                    dec_source=enc_str_ptr,
                )
                # Annotate underlying disassembler with decrypted data.
                string.patch(dis, rename=False)

                # Report decoded string.
                self.report.add(metadata.DecodedString(
                    str(string), encryption_key=metadata.EncryptionKey(bytes([key]), "xor")
                ))

    def run(self):
        with self.file_object.disassembly(report=self.report) as dis:
            self.find_strings(dis)
