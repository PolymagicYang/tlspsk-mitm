import dpkt
import cipher_const
from cipher_const import CIPHER_CONST
from py_prf import prf
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
import psk_key_exchange
from enum import Enum
from multiprocessing import Lock
import logging
import sys

class TASKSTATE(Enum):
    KILL = 0
    RESTART = 1
    ClientHello = 2
    ServerHello = 3
    ClientKeyExchange = 4
    NewSessionTicket = 5
    COMMUNICATION = 6
    PASS = 7

class KeyGenerator:
    def __init__(self):
        self.ready_lock = Lock()
        self.client_ready = False
        self.server_ready = False

    def generate(self, isdhe):
        with self.ready_lock:
            return 1

    @property
    def derivekey(self):
        if self.is_generated:
            return self.__derivekey
        else:
            return None

    @property
    def wait_derivekey(self):
        while True:
            if self.is_generated:
                return self.__derivekey

    @property
    def is_generated(self):
        # Private Usage, User outside this class mustn't use this method.
        with self.ready_lock:
            result = self.client_ready and self.server_ready
        return result

class PktHandler:
    def __init__(self):
        self.PSK = {b"server2": b"123456", b"client2": b"123456"}
        self.DEFAULT_PSK = b"123456"
        self.visited = set()
        self.MASTER_KEY = None
        self.PRE_MASTER = None
        self.SERVER_RND = None
        self.CLIENT_RND = None
        self.CIPHER_SUITE = None
        self.CLIENT_PORT = None
        self.SERVER_PORT = None
        self.DERIVE_KEYS = {}
        self.CIPHER_META = {}
        self.handshake_bytes = bytearray()
        self.client_handshake_bytes = bytearray()
        self.server_handshake_bytes = bytearray()
        self.is_key_generated = False 
        self.SEQUENCE_NUM = 0
        self.PROTO_VERSION = None
        self.STATE = "HANDSHAKE"
        self.isdhe = False
        self.CIPHER_DECRYPTORS = {
            "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256": self.decrypt_chacha_poly_dhe,
            "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256": self.decrypt_chacha_poly,
            "TLS_PSK_WITH_AES_256_GCM_SHA384": self.decrypt_aes_gcm,
            "TLS_PSK_WITH_AES_128_GCM_SHA256": self.decrypt_aes_gcm,
            "TLS_PSK_WITH_AES_128_CBC_SHA256": self.decrypt_aes_cbc,
            "TLS_PSK_WITH_AES_256_CBC_SHA": self.decrypt_aes_cbc,
            "TLS_PSK_WITH_NULL_SHA256": self.decrypt_null,
        }
        self.key_lock = Lock()

        root = logging.getLogger()
        logging.basicConfig(filename="./parser.log", level=logging.DEBUG)
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        root.addHandler(handler)

    def decrypt_aes_cbc(self, ct_record, sport, sip):
        # trunc mac
        cipher_text = ct[:len(ct) - self.CIPHER_SUITE.mac_size]
        packet_type = ct_record[0:1] 
        proto_version = ct_record[1:3]
        ct_len = int(ct_record[3:5].hex(), 16)
        ct = ct_record[5:5+ct_len]

        algo, mode = self.cipher_meta(sport)
        cipher = Cipher(algo, mode)
        decryptor = cipher.decryptor()
        return decryptor.update(cipher_text) + decryptor.finalize()
        
    def decrypt_aes_gcm(self, ct_record, cur_port, sip):
        if cur_port == self.CLIENT_PORT:
            key = self.DERIVE_KEYS["client_write_key"]
            iv = self.DERIVE_KEYS["client_iv"]
        else:
            key = self.DERIVE_KEYS["server_write_key"]
            iv = self.DERIVE_KEYS["server_iv"]

        # RFC 5246: 6.2.3.3.
        # additional data: 8 (seq_num) + 1 (packet_type) + 2 (proto_version) + 2 (length).
        seq_num = self.SEQUENCE_NUM.to_bytes(8, "big") # seq_num is 64 bit long.

        packet_type = ct_record[0:1] 
        proto_version = ct_record[1:3]
        ct_len = int(ct_record[3:5].hex(), 16)
        ct = ct_record[5:5+ct_len]

        length = (len(ct) - 24).to_bytes(2, "big")

        # additional data.
        aad = b"".join([seq_num, packet_type, proto_version, length]) 
        nonce = b"".join([iv, ct[:8]])

        aesgcm = AESGCM(key)

        # last 16 bytes of ciphertext as the tag in GCM.
        tag = ct[-16:]
        ct = ct[8:]
        logging.debug("ct:" + ct.hex() + "len:" + str(len(ct)))
        logging.debug("tag:" + tag.hex() + "len:" + str(len(tag)))
        logging.debug("nonce:" + nonce.hex() + "len:" + str(len(nonce)))
        logging.debug("aad:" + aad.hex() + "len:" + str(len(aad)))
        return aesgcm.decrypt(nonce, ct, aad)

    def decrypt_chacha_poly_dhe(self, ct_record, cur_port, sip):
        if cur_port == self.CLIENT_PORT:
            self.DERIVE_KEYS = self.CLIENT_DERIVE_KEYS
        else:
            self.DERIVE_KEYS = self.SERVER_DERIVE_KEYS

        return self.decrypt_chacha_poly(ct_record, cur_port, sip)

    def encrypt_chacha_poly(self, ct_record, plain_data, cur_port, sip):
        if cur_port == self.CLIENT_PORT:
            key = self.DERIVE_KEYS["client_write_key"]
            iv = self.DERIVE_KEYS["client_iv"]
        else:
            key = self.DERIVE_KEYS["server_write_key"]
            iv = self.DERIVE_KEYS["server_iv"]

        seq_num = self.SEQUENCE_NUM.to_bytes(8, "big")
        packet_type = ct_record[0:1] 
        proto_version = ct_record[1:3]
        length = len(plain_data).to_bytes(2, "big")

        aad = b"".join([seq_num, packet_type, proto_version, length])
        padded_seq = self.SEQUENCE_NUM.to_bytes(12, "big")
        nonce = bytes([_a ^ _b for _a, _b in zip(iv, padded_seq)])

        chacha = ChaCha20Poly1305(key)
        return chacha.encrypt(nonce, plain_data, aad)


    def decrypt_chacha_poly(self, ct_record, cur_port, sip):
        if cur_port == self.CLIENT_PORT:
            key = self.DERIVE_KEYS["client_write_key"]
            iv = self.DERIVE_KEYS["client_iv"]
        else:
            key = self.DERIVE_KEYS["server_write_key"]
            iv = self.DERIVE_KEYS["server_iv"]

        # RFC 5246: 6.2.3.3.
        # additional data: 8 (seq_num) + 1 (packet_type) + 2 (proto_version) + 2 (length).
        seq_num = self.SEQUENCE_NUM.to_bytes(8, "big") # seq_num is 64 bit long.

        packet_type = ct_record[0:1] 
        proto_version = ct_record[1:3]
        ct_len = int(ct_record[3:5].hex(), 16)
        ct = ct_record[5:5+ct_len]

        length = (ct_len - 16).to_bytes(2, "big")

        # additional data.
        aad = b"".join([seq_num, packet_type, proto_version, length]) 
        padded_seq = self.SEQUENCE_NUM.to_bytes(12, "big")
        nonce = bytes([_a ^ _b for _a, _b in zip(iv, padded_seq)])

        chacha = ChaCha20Poly1305(key)

        # last 16 bytes of ciphertext as the tag in GCM.
        tag = ct[-16:]

        logging.debug("key: " + key.hex())
        logging.debug("ct, tag, nonce:")
        logging.debug("ct:" + ct.hex() + "len:" + str(len(ct)))
        logging.debug("tag:" + tag.hex() + "len:" + str(len(tag)))
        logging.debug("nonce:" + nonce.hex() + "len:" + str(len(nonce)))
        logging.debug("aad:" + aad.hex() + "len:" + str(len(aad)))
        return chacha.decrypt(nonce, ct, aad)

    def decrypt_null(self, cmeta):
        return 1

    def handle_clienthello(self, record, tcp, tls):
        self.CLIENT_RND = tls.data.random
        self.CLIENT_PORT = tcp.sport
        self.handshake_bytes.extend(record.data)

    def handle_serverhello(self, record, tcp, tls):
        self.CIPHER_SUITE = tls.data.ciphersuite
        self.SERVER_PORT = tcp.sport
        self.SERVER_RND = tls.data.random
        self.handshake_bytes.extend(record.data)

    def handle_serverkeyexchange(self, record, tcp, tls):
        if self.CIPHER_SUITE.kx in ["DHE", "ECDHE"]:
            data = bytes(tls.data)
            length = int(data[:2].hex(), 16)
            if length == 0:
                # No hint provided, use default psk.
                # length of nonce.
                length = data[3]
                psk = self.DEFAULT_PSK
            else:
                psk_hint = data[2:2+length]
                psk = self.PSK[psk_hint]

            dhe_part = data[2+length:]
            # 0x03: named curve, 0x001d: X25519 curve, 0x20: length of params, 32 bytes.
            if dhe_part[0] == 3:
                # named curve.
                if int(dhe_part[1:3].hex(), 16) == 29:
                    # x25519 curve.
                    self.dhe_privkey = X25519PrivateKey.generate()
                    param_len = dhe_part[3]
                    pubk_in_pkt = X25519PublicKey.from_public_bytes(dhe_part[4:4+param_len])
                    self.server_shared_key = self.dhe_privkey.exchange(pubk_in_pkt)

                    # replace last len of param elem.data with public key.
                    temp_data = bytearray(record.data)
                    public_key = self.dhe_privkey.public_key()
                    pk_bytes = public_key.public_bytes(
                        encoding = serialization.Encoding.Raw,
                        format = serialization.PublicFormat.Raw
                    )
                    temp_data[-param_len:] = pk_bytes
                    # Should fork a new handshake bytes stream for client usage.
                    self.server_handshake_bytes = self.handshake_bytes[:]
                    self.server_handshake_bytes.extend(record.data)

                    self.SERVER_PRE_MASTER = psk_key_exchange.derive_ps(psk, self.server_shared_key).get_payload()
                    self.client_handshake_bytes = self.handshake_bytes[:]
                    self.client_handshake_bytes.extend(bytes(temp_data))
                    self.isdhe = True
        else:
            self.handshake_bytes.extend(record.data)

    def handle_serverhellodone(self, record, session_data):
        if self.isdhe:
            # To maintain two different handshake bytes.
            self.server_handshake_bytes.extend(record.data)
            self.client_handshake_bytes.extend(record.data)

            public_key = self.dhe_privkey.public_key()
            pk_bytes = public_key.public_bytes(
                encoding = serialization.Encoding.Raw,
                format = serialization.PublicFormat.Raw
            )

            # ServerHello, ServerKeyExchange, [pb_bytes] , ServerHelloDone.
            # Should plus record header.
            param_len = len(pk_bytes)
            session_data[-(param_len + len(record)):-len(record)] = pk_bytes 
            self.MODIFIED_TLS_DHE = bytes(session_data)
        else:
            self.handshake_bytes.extend(record.data)

    def handle_clientfinished(self, finished_record, sport):
        # verify data length for CTR_OMAC cipher suites is 32, CNT_IMIT is 12
        verifydata_length = 32 if self.isdhe else 12

        if self.CIPHER_SUITE.mac == "SHA256":
            hashfn = hashes.SHA256()
        elif self.CIPHER_SUITE.mac == "SHA384":
            hashfn = hashes.SHA384()
        digest = hashes.Hash(hashfn)
        if self.isdhe:
            # We will send modified client verify data to the server, so the digest needs to follow the server's handshake records, not the client's.
            digest.update(bytes(self.server_handshake_bytes))
        else:
            digest.update(bytes(self.handshake_bytes))

        digest = digest.finalize()

        verify_data = prf(self.MASTER_KEY, b"client finished", digest, hashfn, verifydata_length)

        plain_text = self.CIPHER_DECRYPTORS[self.CIPHER_SUITE.name](finished_record, sport, sport)

        logging.debug("verify data for client handshakes: " + verify_data.hex())
        logging.debug("client finished data is: " + plain_text.hex())
        if self.isdhe:
            # Encrypt verify data using client derive key.
            self.DERIVE_KEYS = self.CLIENT_DERIVE_KEYS
            self.client_handshake_bytes.extend(verify_data)
            # Verify data sent to server is generated by us, so extend messages with modified messeges.
            self.server_handshake_bytes.extend(plain_text)

            verify_data = self.encrypt_chacha_poly(finished_record, verify_data, sport, sport)

            temp = bytearray(self.MODIFIED_TLS_DHE)
            temp[-len(verify_data):] = verify_data
            self.MODIFIED_TLS_DHE = bytes(temp)

        self.handshake_bytes.extend(plain_text)
        
    def handle_sessionticket(self, session_data):
        if self.isdhe:
            self.server_handshake_bytes.extend(session_data)
            self.client_handshake_bytes.extend(session_data)
        else:
            print("session data: " + session_data.hex())
            self.handshake_bytes.extend(session_data)

    def handle_serverfinished(self):
        # verify data length for CTR_OMAC cipher suites is 32, CNT_IMIT is 12
        verifydata_length = 32 if self.isdhe else 12

        if self.CIPHER_SUITE.mac == "SHA256":
            hashfn = hashes.SHA256()
        elif self.CIPHER_SUITE.mac == "SHA384":
            hashfn = hashes.SHA384()
        digest = hashes.Hash(hashfn)
        if self.isdhe:
            digest.update(bytes(self.server_handshake_bytes))
        else:
            digest.update(bytes(self.handshake_bytes))
        digest = digest.finalize()
        
        verify_data = prf(self.MASTER_KEY, b"server finished", digest, hashfn, verifydata_length)

        logging.debug("verify data for server handshakes: " + verify_data.hex())

        if self.isdhe:
            temp = bytearray(self.MODIFIED_TLS_DHE)
            temp[-verifydata_length:] = verify_data
            self.MODIFIED_TLS_DHE = bytes(temp)

    def handle_clientkeyexchange(self, session_records, record, tcp, tls):
        data = bytes(tls.data)
        length = int(data[:2].hex(), 16)
        psk_hint = data[2:2+length]
        psk = self.PSK[psk_hint]

        if self.CIPHER_SUITE.kx in ["ECDHE", "DHE"]:
            dhe_part = data[2+length:]
            param_len = dhe_part[0]
            pubk_in_pkt = X25519PublicKey.from_public_bytes(dhe_part[1:1+param_len])
            self.client_shared_key = self.dhe_privkey.exchange(pubk_in_pkt)
            pubkey = self.dhe_privkey.public_key().public_bytes(
                encoding = serialization.Encoding.Raw,
                format = serialization.PublicFormat.Raw
            )

            temp_tls_record = bytearray(bytes(record))
            # MODIFIED_DHE_TLS must includes tls record header.
            temp_tls_record[-param_len:] = pubkey
            # Repalce first part (Client Key Exchange) with modified pkt (temp_data).
            temp_tls_record.extend(session_records[len(bytes(record)):])
            self.MODIFIED_TLS_DHE = bytes(temp_tls_record)

            # client trace should append unmodified packet, because it's sent from the client, client already record the unmodifed packet.
            self.client_handshake_bytes.extend(record.data)

            self.CLIENT_PRE_MASTER = psk_key_exchange.derive_ps(psk, self.client_shared_key).get_payload()

            # server trace should append modified packet, because we need to send modifed packet to the server.
            # replace last len of param record.data with public key.
            temp_data = bytearray(record.data)
            temp_data[-param_len:] = pubkey
            self.server_handshake_bytes.extend(bytes(temp_data))
        else:
            self.PRE_MASTER = psk_key_exchange.derive_ps(psk).get_payload()
            self.handshake_bytes.extend(record.data)

    # Return (packet status, is dhe) pair.
    def handle_packet(self, tls_data, data, seq) -> (int, bool):
        self.SEQUENCE_NUM = seq
        tcp = dpkt.tcp.TCP(data) 

        if tcp.seq in self.visited:
            return (TASKSTATE.PASS.value, self.isdhe)
        else:
            self.visited.add(tcp.seq)

        try:
            msgs, i = dpkt.ssl.tls_multi_factory(tcp.data)
        except:
            logging.error("Only support TLS-PSK.")
            return (TASKSTATE.KILL.value, self.isdhe)

        first_pkt = msgs[0]
        if not isinstance(first_pkt, dpkt.ssl.TLSRecord):
            logging.error("Non supported protocol: %s" % elem.__class__.__name__)
            return (TASKSTATE.KILL.value, self.isdhe)

        tls = dpkt.ssl.RECORD_TYPES[first_pkt.type](first_pkt.data)
        """
            >> Client Hello
            
            << Serve Hello, (Server Key Exchange), Server Hello Done

            >> Client Key Exchange, Change Cipher Spec, Finished

            << New Session Ticket, Change Cipher Spec, Finished
    
            >> Communication         
        """
        if isinstance(tls, dpkt.ssl.TLSAppData):
            logging.info("start parse.")
            ct_record = bytes(first_pkt)
            plain_text = self.CIPHER_DECRYPTORS[self.CIPHER_SUITE.name](ct_record, tcp.sport, tcp.sport)
            logging.info("plain text:" + plain_text.hex())
            return (TASKSTATE.COMMUNICATION.value, self.isdhe)

        elif isinstance(tls, dpkt.ssl.TLSChangeCipherSpec):
            if not self.handle_changeCipherSpec(tcp.sport):
                return (TASKSTATE.KILL.value, self.isdhe)

        elif isinstance(tls, dpkt.ssl.TLSHandshake):
            handshake_type, handshake = dpkt.ssl.HANDSHAKE_TYPES[tls.type]
            
            if handshake_type == "ClientHello":
                self.handle_clienthello(first_pkt, tcp, tls)        
                logging.debug("ClientHello, handshake bytes:" + first_pkt.data.hex())
                return (TASKSTATE.ClientHello.value, False)

            elif handshake_type == "ServerHello":
                # process serverhello handshake part.
                logging.debug("ServerHello, handshake bytes:" + first_pkt.data.hex())
                self.handle_serverhello(first_pkt, tcp, tls)

                # second packet doesn't exist if there's no server hint.
                sk_exchange = msgs[1] if len(msgs) == 3 else None
                if sk_exchange is not None:
                    tls = dpkt.ssl.RECORD_TYPES[sk_exchange.type](sk_exchange.data)
                    # Warn: server key exchange will change self.isdhe (side effect)
                    logging.debug("ServerKeyExchange, handshake bytes:" + sk_exchange.data.hex())
                    self.handle_serverkeyexchange(sk_exchange, tcp, tls)

                # server hello done needs to create 3 different handshake streams if dhe enabled.
                s_hello_done_record = msgs[-1]
                tls = dpkt.ssl.RECORD_TYPES[s_hello_done_record.type](s_hello_done_record.data)

                session_data = bytearray(b"".join(list(map(lambda x: bytes(x), msgs))))
                logging.debug("ServerHelloDone, handshake bytes:" + s_hello_done_record.data.hex())
                self.handle_serverhellodone(s_hello_done_record, session_data)

                return (TASKSTATE.ServerHello.value, self.isdhe)

            elif handshake_type == "ClientKeyExchange":
                session_records = bytearray(b"".join(list(map(lambda x: bytes(x), msgs))))

                # MODIFIED DHE has changed.
                self.handle_clientkeyexchange(session_records, first_pkt, tcp, tls)
                
                # TODO: In parallel.
                self.handle_changeCipherSpec(tcp.sport)

                self.handle_clientfinished(bytes(msgs[-1]), tcp.sport)
                return (TASKSTATE.ClientKeyExchange.value, self.isdhe)

            elif handshake_type == "NewSessionTicket":
                self.handle_sessionticket(first_pkt.data)
                self.handle_serverfinished()
                return (TASKSTATE.NewSessionTicket.value, self.isdhe)

    def handle_changeCipherSpec(self, sport):
        # No need to generate key twice.
        
        if self.is_key_generated:
            return True

        if self.isdhe:
            if self.CLIENT_PRE_MASTER is None or self.SERVER_PRE_MASTER is None:
                logging.error("Failed to parse pre_secret")
                return False
            self.PRE_MASTER = self.CLIENT_PRE_MASTER
            self.handshake_bytes = self.client_handshake_bytes
            result_client = self.changeCipherSpec()
            self.CLIENT_DERIVE_KEYS = self.DERIVE_KEYS

            self.PRE_MASTER = self.SERVER_PRE_MASTER
            self.handshake_bytes = self.server_handshake_bytes
            result_server = self.changeCipherSpec()
            self.SERVER_DERIVE_KEYS = self.DERIVE_KEYS

            logging.debug("client_handshake_bytes:" + bytes(self.client_handshake_bytes).hex())
            logging.debug("server_handshake_bytes:" + bytes(self.server_handshake_bytes).hex())
            return result_server and result_client

        if self.PRE_MASTER is None:
            logging.error("Failed to parse pre_secret")
            return False

        result = self.changeCipherSpec()
        return result

    # return True if keep parsing stream, otherwise return TASKSTATE.KILL.value.
    def changeCipherSpec(self):
        if self.CIPHER_SUITE.mac == "SHA256":
            hashfn = hashes.SHA256()
        elif self.CIPHER_SUITE.mac == "SHA384":
            hashfn = hashes.SHA384()
        digest = hashes.Hash(hashfn)
        digest.update(bytes(self.handshake_bytes))
        digest = digest.finalize()

        logging.debug("digest:" + digest.hex())
        # generate extended master secret, if not, try master secret directly
        logging.debug("premaster" + self.PRE_MASTER.hex())

        self.MASTER_KEY = prf(self.PRE_MASTER, b"extended master secret", digest, hashfn, 48)

        logging.info("master key:" + self.MASTER_KEY.hex())

        if self.SERVER_RND is None or self.CLIENT_RND is None:
            logging.error("Failed to parse rnd")
            return False 
        RND = b"".join([self.SERVER_RND, self.CLIENT_RND])
        if self.CIPHER_SUITE is None:
            logging.error("Failed to parse cipher suite.")
            return False 

        # todo: refactor.
        self.CIPHER_META["cipher"] = self.CIPHER_SUITE.cipher.split("_")[0]
        logging.info("cipher-name:" + self.CIPHER_SUITE.cipher)

        self.CIPHER_META["mode"] = self.CIPHER_SUITE.mode

        # order: client_mac, server_mac, client_write_key, server_write_key, client_iv, srever_iv

        ciphers_info = CIPHER_CONST[self.CIPHER_SUITE.name]
        iv_len = ciphers_info.iv_len
        cipher_len = ciphers_info.key_size
        mac_len = ciphers_info.mac_len
        
        total_len = iv_len * 2 + cipher_len * 2 + mac_len * 2

        key_block = psk_key_exchange.derive_key_block(self.MASTER_KEY, RND, total_len, hashfn)

        logging.debug(key_block.hex())
        pairs = [("client_mac", mac_len), ("server_mac", mac_len), ("client_write_key", cipher_len), ("server_write_key", cipher_len), ("client_iv", iv_len), ("server_iv", iv_len)]

        # Generate derived key.
        index = 0
        for pair in pairs:
            name, length = pair
            self.DERIVE_KEYS[name] = key_block[index:index+length]
            index += length
        self.is_key_generated = True

        return True

    def cipher_meta(self, port):
        # should add ip support packet identification.
        algo_fn = eval("algorithms." + self.CIPHER_META["cipher"])
        mode_fn = eval("modes." + self.CIPHER_META["mode"])
        if port == self.CLIENT_PORT:
            algo = algo_fn(self.DERIVE_KEYS["client_write_key"])
            mode = mode_fn(self.DERIVE_KEYS["client_iv"])
        else:
            algo = algo_fn(self.DERIVE_KEYS["server_write_key"])
            mode = mode_fn(self.DERIVE_KEYS["server_iv"])

        return (algo, mode)

