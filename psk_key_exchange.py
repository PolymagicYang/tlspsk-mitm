from py_prf import prf
import cryptography
from cryptography.hazmat.primitives import hashes 
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import subprocess
import logging

# handshake_msg = b"".join([client_hello, server_hello, server_key_exchange, server_hello_done, client_key_exchange])

# if the PSK is N octets long, concatenate a uint16 with the value N,
# N zero octets, a second uint16 with the value N, and the PSK itself.
class PS:
    def __init__(self, psk: bytes, dhe_params: bytes):
        if dhe_params == None: 
            logging.info("Premaster: Non dhe")
            n = len(psk)
            # bit endian, most significant first, 02 -> 0002
            other_secret = n.to_bytes(2, "big") + n * b"\x00" + n.to_bytes(2, "big")
            self.i_psk = len(other_secret)
            self.payload = other_secret + psk
        else:
            logging.info("Premaster: Dhe")
            lenofZ = len(dhe_params)
            lenofS = len(psk)
            other_secret = lenofZ.to_bytes(2, "big") + dhe_params + lenofS.to_bytes(2, "big")
            self.i_psk = len(other_secret)
            self.payload = other_secret + psk

        logging.debug("curr payload is:" + self.payload.hex())

    def get_other_secret(self) -> bytes:
        return self.payload[:self.i_psk]

    def get_psk(self) -> bytes:
        return self.payload[self.i_psk:]

    def get_payload(self) -> bytes:
        return self.payload

def derive_key_block(master_secret, rnd, req_len, hashfn):
    return prf(master_secret, b"key expansion", rnd, hashfn, req_len)

def derive_ps(psk: bytes, dhe_params = None) -> bytes:
    return PS(psk, dhe_params)

