from enum import Enum

# (key_size, block_size) pair.
CIPHER_LENS = {
        "RC4": (0, 0),
        "AES_128": (16, 16),
        "AES_256": (32, 16)
}

MAC_LENS = {
        "SHA": 20,
        "SHA256": 32,
        "SHA384": 48,
}

chacha = {
        "iv_len": 16,
        "mac_len": 0,
        "key_size": 32,
        "block_size": 0
}

aes_256_gcm = {
        "iv_len": 4, 
        "mac_len": 0,
        "key_size": 32,
        "block_size": 16 
}

class MetaInfo:
    def __init__(self, iv_len, mac_len, key_size, block_size):
        self.iv_len = iv_len
        self.mac_len = mac_len
        self.key_size = key_size
        self.block_size = block_size

class CIPHER_TYPE(Enum):
    ECDHE_CHACHA = "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256"
    CHACHA = "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256"
    AES_256_GCM = "TLS_PSK_WITH_AES_256_GCM_SHA384"
    AES_128_GCM = "TLS_PSK_WITH_AES_128_GCM_SHA256"
    AES_128_CBC = "TLS_PSK_WITH_AES_128_CBC_SHA256"
    AES_256_CBC = "TLS_PSK_WITH_AES_256_CBC_SHA"
    NULL = "TLS_PSK_WITH_NULL_SHA256"

CIPHER_CONST = {
    CIPHER_TYPE.ECDHE_CHACHA.value: MetaInfo(12, 0, 32, 16),
    CIPHER_TYPE.CHACHA.value: MetaInfo(12,0,32,16),
    CIPHER_TYPE.AES_256_GCM.value: MetaInfo(4, 0, 32, 16),
    CIPHER_TYPE.AES_128_GCM.value: MetaInfo(4, 0, 16, 16),
    CIPHER_TYPE.AES_128_CBC.value: MetaInfo(16, 32, 16, 16),
    CIPHER_TYPE.AES_256_CBC.value: MetaInfo(16, 20, 32, 16),
    CIPHER_TYPE.NULL.value: MetaInfo(0, 0, 0, 0)
}
