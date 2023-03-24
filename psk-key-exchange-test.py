from py_prf import prf
import cryptography
from cryptography.hazmat.primitives import hashes 
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import subprocess

client_random = bytes.fromhex("15555de81980369d7139123a23c40c156f9d67699dab10cc07d1fdf4253ec218")
server_random = bytes.fromhex("166bba024a170a9879be793f5e1cbd8e9b0142e8274379e04f0270b3551926ec")

client_hello = bytes.fromhex("010000dd030315555de81980369d7139123a23c40c156f9d67699dab10cc07d1fdf4253ec21800006200ad00abccaeccadccacc0abc0a7c06fc06d00a9ccabc0a9c0a5c06b00ac00aac0aac0a6c06ec06c00a8c0a8c0a4c06ac03800b700b3c09bc099c09700afc095c03700b600b2c09ac098c09600aec094c03600950091008dc03500940090008c00ff01000052000b000403000102000a000c000a001d0017001e00190018002300000016000000170000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602")
server_hello = bytes.fromhex("020000390303166bba024a170a9879be793f5e1cbd8e9b0142e8274379e04f0270b3551926ec00008d000011ff01000100002300000016000000170000")
server_key_exchange = bytes.fromhex("0c000009000773657276657232")
server_hello_done = bytes.fromhex("0e000000")
client_key_exchange = bytes.fromhex("100000090007636c69656e7432")
handshake_msg = b"".join([client_hello, server_hello, server_key_exchange, server_hello_done, client_key_exchange])

# if the PSK is N octets long, concatenate a uint16 with the value N,
# N zero octets, a second uint16 with the value N, and the PSK itself.
class PS:
    def __init__(self, psk: bytes):
        n = len(psk)
        # bit endian, most significant first, 02 -> 0002
        other_secret = n.to_bytes(2, "big") + n * b"\x00" + n.to_bytes(2, "big")
        self.i_psk = len(other_secret)
        self.payload = other_secret + psk

    def get_other_secret(self) -> bytes:
        return self.payload[:self.i_psk]

    def get_psk(self) -> bytes:
        return self.payload[self.i_psk:]

    def get_payload(self) -> bytes:
        return self.payload

def derive_key_block(master_secret, rnd, req_len):
    return prf(master_secret, b"key expansion", rnd, cryptography.hazmat.primitives.hashes.SHA256(), req_len)

def derive_ps(psk: bytes) -> bytes:
    return PS(psk)

a = derive_ps(b"123456").get_payload()
# print("premaster secret: ", a.hex())

cs_random = b"".join([client_random, server_random])

digest = hashes.Hash(hashes.SHA256())
digest.update(handshake_msg)
digest = digest.finalize()

# print("hash session: ", digest.hex())
# print("session:", b"extended master secret".hex() + digest.hex())

master_key = prf(a, b"extended master secret", digest, hashes.SHA256(), 48)
print("master_key:", master_key.hex())

key_block = derive_key_block(master_key, b"".join([server_random, client_random]), 136) 
# print(key_block.hex())

result = {
    "client_mac_key": key_block[0:20],
    "server_mac_key": key_block[20:40],
    "client_enc_key": key_block[40:72],
    "server_enc_key": key_block[72:104],
    "client_iv": key_block[104:120],
    "server_iv": key_block[120:136],
}

# subprocess.check_output(["openssl", "enc", "-d", "-aes-256-cbc", "-in", "./digest.txt", "-K", result["client_enc_key"], "-iv", result["client_iv"]])

cipher = Cipher(algorithms.AES(result["server_enc_key"]), modes.CBC(result["server_iv"]))
decryptor = cipher.decryptor()
encryptor = cipher.encryptor()
buf = bytearray(100)
enc = b"ping\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
len_enc = encryptor.update_into(enc, buf)
ct = bytes(buf[:len_enc]) + encryptor.finalize()

print(ct.hex())
with open("./digest.txt", "rb") as f:
    data = f.read()

print(data.hex())
len_dec = decryptor.update_into(data, buf)
print(bytes(buf[:len_dec]).hex(), bytes(buf[:len_dec]))

