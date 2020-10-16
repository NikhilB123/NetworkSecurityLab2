#BKCTL# begin_output: http_proxy.py
import asyncio, time, struct
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac as crypto_hmac # avoid name collision
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import NameOID
from scapy.all import *
from scapy.layers.tls.keyexchange import _TLSSignature
from scapy.layers.tls.handshake import _TLSCKExchKeysField
from datetime import datetime, timedelta
from urllib.parse import urlparse

load_layer("tls")

class Debug:
    def __init__(self):
        self.enabled = False
    def print(self, *args, **kargs):
        if not self.enabled: return
        print(*args, **kargs)
    def scapy_show(self, pkt):
        if not self.enabled: return
        pkt.show2()
debug = Debug()

class TLSSession:
    def __init__(self):
        # manually set value
        self.tls_version = 0x303
        self.read_seq_num = 0
        self.write_seq_num = 0
        self.PRF = PRF()

        self.client_time = None
        self.client_random_bytes = None
        
        self.server_time = None
        self.server_random_bytes = None

        self.server_rsa_privkey = None
        self.client_dh_params = None

        self.mac_key_size = 20
        self.enc_key_size = 16
        #self.iv_size = 16

        self.handshake = True

        # automatically calculated
        self.client_random = None
        self.server_random = None
        self.server_dh_params = ServerDHParams()
        self.server_dh_params.fill_missing()
        self.server_dh_privkey = self.server_dh_params.tls_session.server_kx_privkey
        self.client_dh_pubkey = None
        self.pre_master_secret = None
        self.master_secret = None
        self.read_mac = None
        self.write_mac = None
        self.read_enc = None
        self.write_enc = None
        self.read_iv = None
        self.write_iv = None
        self.key_block_len = (2*self.mac_key_size)+(2*self.enc_key_size)#+(2*self.iv_size)

        self.handshake_messages = b""

    def set_client_random(self, time_part, random_part):
        # STUDENT TODO
        """
        1. set client_time, client_bytes
        2. calculate client_random. There is a method for this
        """
        self.client_time = time_part 
        self.client_random_bytes = random_part
        self.client_random = self.time_and_random(time_part, random_part)


    def set_server_random(self):
        # STUDENT TODO
        """
        1. set server_time, server_bytes
        2. calculate server_random. There is a method for this
        """
        self.server_time = int(time.time())
        self.server_random_bytes = randstring(28)
        self.server_random = self.time_and_random(self.server_time, self.server_random_bytes)


    def set_server_rsa_privkey(self, rsa_privkey):
        self.server_rsa_privkey = rsa_privkey

    def set_client_dh_params(self, client_params):
        self.client_dh_params = client_params  
        p = pkcs_os2ip(self.server_dh_params.dh_p)
        g = pkcs_os2ip(self.server_dh_params.dh_g)
        pn = dh.DHParameterNumbers(p,g)
        y = pkcs_os2ip(self.client_dh_params.dh_Yc)
        public_key_numbers = dh.DHPublicNumbers(y, pn)
        self.client_dh_pubkey = public_key_numbers.public_key(default_backend())
        self._derive_keys()

    def _derive_keys(self):
        # STUDENT TODO
        """
        1. calculate pre_master_secret
        2. calculate master_secret
        3. calculate a key block
        4. split the key block into read and write keys for enc and mac
        """
        self.pre_master_secret = self.server_dh_privkey.exchange(self.client_dh_pubkey)
        self.master_secret = self.PRF.compute_master_secret(self.pre_master_secret, self.client_random, self.server_random)
        key_block = self.PRF.derive_key_block(self.master_secret, self.server_random, self.client_random, self.key_block_len)

        # look into block order
        index = 0
        # self.write_enc = key_block[:self.enc_key_size]
        # index += self.enc_key_size
        # self.read_enc = key_block[index:self.enc_key_size + index]
        # index += self.enc_key_size
        # self.write_mac = key_block[index:self.mac_key_size + index]
        # index += self.mac_key_size
        # self.read_mac = key_block[index:self.mac_key_size + index]
        self.read_mac = key_block[index:self.mac_key_size + index]
        index += self.mac_key_size
        self.write_mac = key_block[index:self.mac_key_size + index]
        index += self.mac_key_size
        self.read_enc = key_block[index:self.enc_key_size + index]
        index += self.enc_key_size
        self.write_enc = key_block[index:self.enc_key_size + index]

    def tls_sign(self, bytes):
        # sig_alg 0x0401 = sha256+rsa as per our certificate
        # STUDENT TODO
        """
        1. Create a TLSSignature object. set sig_alg to 0x0401
        2. use this object to sign the bytes
        """
        sig = _TLSSignature(sig_alg=0x0401)
        sig._update_sig(bytes, self.server_rsa_privkey)
        return sig

    def decrypt_tls_pkt(self, tls_pkt, **kargs):
        # scapy screws up and changes the first byte if it can't decrypt it
        # from 22 to 23 (handshake to application). Check if this happens and fix
        packet_type = tls_pkt.type
        tls_pkt_bytes = raw(tls_pkt)
        tls_pkt_bytes = struct.pack("!B",packet_type)+tls_pkt_bytes[1:]

        print('type:',tls_pkt.type)
        # STUDENT TODO
        """
        1. The beginning of this function, already provided, extracts the data from scapy
        2. Do the TLS decryption process on tls_pkt_bytes
        3. Technically, you don't have to do the hmac. wget will do it right
        4. But if you check the hmac, you'll know your implementation is correct!
        5. return ONLY the decrypted plaintext data
        6. NOTE: When you do the HMAC, don't forget to re-create the header with the plaintext len!
        """
        # need to account for message header
        type_val = struct.pack('!b', tls_pkt_bytes[0])
        version_val = tls_pkt_bytes[1:3]
        ciphertext_len = tls_pkt_bytes[3:5]
        print('length of ciphertext:', int.from_bytes(ciphertext_len, byteorder='big'))
        tls_pkt_bytes = tls_pkt_bytes[5:]

        # get IV and create decryptor object 
        iv = tls_pkt_bytes[:16]
        aes = algorithms.AES(self.read_enc)
        mode = modes.CBC(iv)
        cipher = Cipher(aes, mode, default_backend())
        decryptor = cipher.decryptor()

        # decrypt ciphertext
        ciphertext = tls_pkt_bytes[16:]
        decrypted_pkt = (decryptor.update(ciphertext) + decryptor.finalize())
        # print(type(decrypted_pkt[-1]))
        # padding = int.from_bytes(decrypted_pkt[-1], byteorder='big')
        padding = decrypted_pkt[-1]
        # remove padding from decrypted packet
        # print('padding bytes:',decrypted_pkt[(-1 * padding - 1):])
        decrypted_pkt = decrypted_pkt[:(-1 * padding - 1)]
        # print('decrypted packet:', decrypted_pkt)

        # extract plaintext + hmac from decrypted ciphertext (remove padding)
        plaintext_bytes = decrypted_pkt[:-1 * self.mac_key_size]
        # get hmac value from plaintext + hmac
        hashed_val = decrypted_pkt[-1 * self.mac_key_size:]

        # compare hmac sent in packet to our own computed hmac
        hmac = crypto_hmac.HMAC(self.read_mac, hashes.SHA1(), default_backend())
        hmac.update(struct.pack('!q', self.read_seq_num) + type_val + version_val + struct.pack('!h', len(plaintext_bytes)) + plaintext_bytes)
        new_hashed_val = hmac.finalize()
        if new_hashed_val != hashed_val:
            # print('sequence num:', self.read_seq_num)
            # print('type_val:', type_val)
            # print('version_val', version_val)
            # print('len plaintext bytes:', len(plaintext_bytes))
            # print('plaintext:', plaintext_bytes)
            # print(struct.pack('q', self.read_seq_num) + type_val + version_val + struct.pack('h', len(plaintext_bytes)) + plaintext_bytes)
            # print('new hashed val:', new_hashed_val, 'len:', len(new_hashed_val))
            # print('old hashed val:', hashed_val, 'len:', len(hashed_val))
            raise ValueError("Hashes are not equal!")
        self.read_seq_num += 1

        return plaintext_bytes

    def encrypt_tls_pkt(self, tls_pkt):
        pkt_type = tls_pkt.type
        tls_pkt_bytes = raw(tls_pkt)

        # scapy can make some mistakes changing the first bytes on handshakes
        if tls_pkt_bytes[0] != pkt_type:
            tls_pkt_bytes = struct.pack("!B",pkt_type)+tls_pkt_bytes[1:]
            
        plaintext_msg = tls_pkt.msg[0]
        plaintext_bytes = raw(plaintext_msg)
        
        # STUDENT TODO
        """
        1. the beginning of this function, already provided, extracts the data from scapy
        2. Do the TLS encryption process on the plaintext_bytes
        3. You have to do hmac. This is the write mac key
        4. You have to compute a pad
        5. You can use os.urandom(16) to create an explicit IV
        6. return the iv + encrypted data
        """
        # generate hash of plaintext
        hmac = crypto_hmac.HMAC(self.write_mac, hashes.SHA1(), default_backend())
        seq_num = struct.pack('!q', self.write_seq_num)
        type_num = struct.pack('!b', tls_pkt_bytes[0])
        version_num = tls_pkt_bytes[1:3]
        len_num = struct.pack('!h', len(plaintext_bytes))
        hmac.update(seq_num + type_num + version_num + len_num + plaintext_bytes)
        # print('\n\n\n',seq_num + type_num + version_num + len_num + plaintext_bytes,'\n\n\n')
        hashed_val = hmac.finalize()

        # create cipher encryption object
        aes = algorithms.AES(self.write_enc)
        iv = os.urandom(16)
        mode = modes.CBC(iv)
        cipher = Cipher(aes, mode, default_backend())
        encryptor = cipher.encryptor()
        
        # encrypt plaintext + hashed plaintext + padding + padding val
        padding = b""
        remainder = (len(plaintext_bytes) + len(hashed_val) + 1) % 16
        amount_to_pad_by = (16 - remainder)
        if amount_to_pad_by < 16:
            padding = bytes([amount_to_pad_by]) * (amount_to_pad_by) 
        print('padding:', padding + bytes([amount_to_pad_by]))
        ciphertext = encryptor.update(plaintext_bytes + hashed_val + padding + bytes([amount_to_pad_by])) + encryptor.finalize()
        print('length of iv + ciphertext:', len(iv + ciphertext))
        print('length of iv:', len(iv))
        print('length of ciphertext:', len(ciphertext))
        self.write_seq_num += 1
        return type_num + tls_pkt_bytes[1:3] + struct.pack('!h', len(iv + ciphertext)) + iv + ciphertext

    def record_handshake_message(self, m):
        self.handshake_messages += m

    def compute_handshake_verify(self, mode):
        # STUDENT TODO
        """
        1. use PRF.compute_verify_data to compute the handshake verify data
            arg_1: the string "server"
            arg_2: mode
            arg_3: all the handshake messages so far
            arg_4: the master secret
        """
        res = self.PRF.compute_verify_data("server", mode, self.handshake_messages, self.master_secret)
        return res

    def time_and_random(self, time_part, random_part=None):
        if random_part is None:
            random_part = randstring(28)
        return struct.pack("!I",time_part) + random_part
        
class TLS_Visibility:
    def __init__(self, tls_cert, priv_key):
        self.session = TLSSession()
        self.load_crypto(tls_cert, priv_key)

    def load_crypto(self, cryptography_cert, cryptography_private_key):
        cert_der_bytes = cryptography_cert.public_bytes(serialization.Encoding.DER)
        self.cert = Cert(X509_Cert(cert_der_bytes))
        privatekey_pem_bytes = cryptography_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption())
        self.private_key = PrivKey(privatekey_pem_bytes)

    def encrypt_data(self, data):
        # STUDENT TODO
        """
        Actually, we did this one for you because it was pretty
        simple. But we want you to see that you take data, 
        put it into a TLS application packet, and then 
        encrypt the packet.
        """
        application_part = TLSApplicationData(data=data)
        application_pkt = TLS(msg=[application_part])
        application_pkt.type = 23
        return self.session.encrypt_tls_pkt(application_pkt)

    def process_tls_handshake(self, tls_pkt, tls_msg):
        if isinstance(tls_msg, TLSClientHello):
            debug.print("Got client hello")
            debug.scapy_show(tls_msg)
 
            self.session.set_server_rsa_privkey(self.private_key)
            self.session.set_server_random()
            # STUDENT TODO
            """ 
            Instructions:
            1. process client hello. set the session client random appropriately
            2. create the server hello. Set cipher=TLS_DHE_RSA_WITH_AES_128_CBC_SHA.val
            3. create the server cert message. Set certs=[self.cert]
            4. create server key exchange.
                params = self.session.server_dh_params
                sig = <signature you calculate>
            5. create server hello done
            6. store in the provided server_hello, server_cert, server_key_exchange,
                and server_hello_done variables
            """
            # 1
            self.session.set_client_random(tls_msg.gmt_unix_time, tls_msg.random_bytes)
            # 2
            server_hello = TLSServerHello(gmt_unix_time=self.session.server_time, 
                                          random_bytes=self.session.server_random_bytes, 
                                          version=0x303, 
                                          cipher=TLS_DHE_RSA_WITH_AES_128_CBC_SHA.val)
            # 3
            server_cert = TLSCertificate(certs=[self.cert])
            # 4
            params = self.session.server_dh_params
            sig = self.session.tls_sign(self.session.client_random + self.session.server_random + raw(params))
            server_key_exchange = TLSServerKeyExchange(params=params, sig=sig)
            # 5
            server_hello_done = TLSServerHelloDone()
            f_session = tlsSession()
            f_session.tls_version = 0x303
            tls_response = TLS(msg=[server_hello, server_cert, server_key_exchange, server_hello_done],
                tls_session=f_session)
            tls_response_bytes = raw(tls_response)
            debug.scapy_show(tls_response)


            self.session.record_handshake_message(raw(tls_msg))
            self.session.record_handshake_message(raw(server_hello))
            self.session.record_handshake_message(raw(server_cert))
            self.session.record_handshake_message(raw(server_key_exchange))
            self.session.record_handshake_message(raw(server_hello_done))

            return tls_response_bytes
        elif isinstance(tls_msg, TLSClientKeyExchange):
            debug.print("Got key exchange")
            debug.scapy_show(tls_msg)
            # STUDENT TODO
            """
            1. process the client key exchange by extracting the "exchkeys"
            2. These can be passed directly to session.set_client_dh_params
            """ 
            exchkeys = ClientDiffieHellmanPublic(tls_msg.exchkeys)

            self.session.set_client_dh_params(exchkeys)
            self.session.record_handshake_message(raw(tls_msg))
                
            
        elif isinstance(tls_msg, TLSFinished):
            debug.print("Got Client Finished")
            debug.scapy_show(tls_msg)
            # STUDENT TODO
            """
            1. process the decrypted TLS finished message. OPTIONALLY, verify the data:
                local_verify_data = session.compute_handshake_verify("read")
                local_verify_data ?= tls_msg.vdata
            2. Create the change cipher spec
            3. store in server_change_cipher_spec
            """
            local_verify_data = self.session.compute_handshake_verify('read')
            if local_verify_data != tls_msg.vdata:
                raise ValueError('VData fields are invalid!')
            self.session.record_handshake_message(raw(tls_msg))
            server_change_cipher_spec = TLSChangeCipherSpec()
            # self.session.record_handshake_message(raw(server_change_cipher_spec))
            msg1 = TLS(msg=[server_change_cipher_spec])
            output = raw(msg1)
            print('change cipher spec bytes',output.hex())

            # STUDENT TODO
            """
            1. create the TLSFinished message. 
                Set v_data to session.compute_handshake_verify("write")
                because of scapy weirdness, set tls_session=f_session
            2. store in server_finished
            """
            f_session = tlsSession()
            f_session.tls_version = 0x303
            vdata=self.session.compute_handshake_verify('write')
            server_finished = TLSFinished(vdata=vdata,
                            tls_session=f_session, msglen=12)
            
            msg2 = TLS(msg=[server_finished], tls_session=f_session)
            
            # MAY BREAK THINGS
            msg2.type = 22


            # STUDENT TODO
            """
            1. encrypt the tls finished message (msg2). You already have a method for this.
            2. store in encrypted_finished
            """
            encrypted_finished = self.session.encrypt_tls_pkt(msg2)
            # encrypted_finished = self.encrypt_data(msg2)
            debug.scapy_show(msg1)
            self.session.handshake = False
            print('output + encrypted', (output+encrypted_finished).hex())
            return output+encrypted_finished
        elif isinstance(tls_msg, Raw):
            # STUDENT TODO
            """
            1. This was a HANDSHAKE message scapy couldn't process. It's because it's encrypted
            2. decrypt the packet to plaintext_data. You should already have a method for this
            3. store in plaintext_data
            4. The provided code already re-creates the TLSFinished from your decrypted data
            """
            plaintext_data = self.session.decrypt_tls_pkt(tls_pkt)
            
            # We re-create the TLS message with the decrypted handshake
            # Then we call `process_tls_handshake` again with this new message
            f_session = tlsSession()
            f_session.tls_version = 0x303
            decrypted_msg = TLSFinished(plaintext_data, tls_session=f_session)
            return self.process_tls_handshake(None, decrypted_msg)
            
        return b""

    def process_tls_data(self, data):
        # STUDENT TODO (kind of)
        """
        Sometimes Asyncio can swallow
        exceptions. If that's happening, you can
        try uncommenting this try except block
        """
        # try:
        #     return self.process_tls_data_unsafe(data)
        # except Exception as e:
        #    return ("failure", e)
        return self.process_tls_data_unsafe(data)

    def process_tls_data_unsafe(self, data):
        output = b""
        if self.session.handshake:
            result_type = "local_response"
        else:
            result_type = "proxy"
        tls_data = TLS(data)
        debug.print("tls data without session")
        debug.scapy_show(tls_data)
        tls_pkts = [tls_data]
        # we are getting TLS messages smushed together as payloads
        next_payload = tls_data.payload
        tls_data.remove_payload()
        while next_payload and isinstance(next_payload, TLS):
            debug.print("got packet of type", next_payload.type)
            tls_pkts.append(next_payload)
            next_payload2 = next_payload.payload
            next_payload.remove_payload()
            next_payload = next_payload2
            debug.print("after detach, type is", tls_pkts[-1].type)
        debug.print("Processing {} packets".format(len(tls_pkts)))
        while tls_pkts:
            tls_pkt = tls_pkts.pop(0)
            if tls_pkt.type == 22: # handshake
                for handshake_data in tls_pkt.msg:
                    response = self.process_tls_handshake(tls_pkt, handshake_data)
                    #self.session.handshake_messages += response
                    output += response
            elif tls_pkt.type == 20:
                debug.print("Got Change Cipher Spec")
                debug.scapy_show(tls_pkt)
            elif tls_pkt.type == 21:
                print("Got Alert")
                raise Exception("Something went wrong with TLS")
            elif tls_pkt.type == 23:
                if self.session.handshake:
                    raise Exception("Got application data while still in handshake")
                # STUDENT TODO
                """
                1. We've received an application data packet. It will be encrypted
                2. decrypt the packet to application_data. You should already have a method for this.
                3. store in application_data
                """
                application_data = self.session.decrypt_tls_pkt(tls_pkt)
                application_pkt = TLSApplicationData(application_data)
                output += application_pkt.data
            else:
                print("Got unknown tls pkt type {}".format(pkt.type))
                tls_pkt.show2()

        return (result_type, output)

class ProxySocket(asyncio.Protocol):

    def __init__(self, proxy):
        self.proxy = proxy

    def connection_made(self, transport):
        self.transport = transport
        self.proxy.proxy_socket = self

    def data_received(self, data):
        debug.print("PROXY RECV:", data)
        self.proxy.handle_remote_response(data)

    def connection_lost(self, exc):
        self.proxy.transport.close()


class TLSFrontend(asyncio.Protocol):
    def __init__(self, tls_cert, tls_key, proxy_port):
        super().__init__()
        self.tls_cert = tls_cert
        self.tls_key  = tls_key
        self.proxy_port = proxy_port
        self.backlog = b""
        
    def connection_made(self, transport):
        peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(peername))
        self.transport = transport
        self.proxy_socket = None
        self.tls_handler = TLS_Visibility(self.tls_cert, self.tls_key)
        coro = asyncio.get_event_loop().create_connection(lambda: ProxySocket(self), "127.0.0.1", self.proxy_port, ssl=False)
        t = asyncio.get_event_loop().create_task(coro)
        t.add_done_callback(self.proxy_connected)
        
    def proxy_connected(self, task):
        if not self.proxy_socket:
            raise Exception("Unable to connect to backend server")
        if self.backlog:
            print("Writing backlog to proxy")
            self.proxy_socket.transport.write(self.backlog)
            self.backlog = b""

    def handle_remote_response(self, data):
        data = self.tls_handler.encrypt_data(data)   
        self.transport.write(data)

    def data_received(self, data):
            
        debug.print("PROXY SEND:", data)

        # Responding with our own TLS response
        result_type, result = self.tls_handler.process_tls_data(data)
        if result_type == "local_response":
            if result: self.transport.write(result)
        elif result_type == "failure":
            self.transport.close()
        elif result_type == "proxy":
            debug.print("Sending decrypted data to server")
            debug.print(result)
            if result: 
                if not self.proxy_socket:
                    self.backlog += result
                else:
                    self.proxy_socket.transport.write(result)

    def connection_lost(self, exc):
        if not self.proxy_socket: return
        self.proxy_socket.transport.close()
        self.proxy_socket = None
        
def main(args): 
    # uncomment the next line to turn on debug
    debug.enabled = True
    frontend_port, backend_port, tls_cert, tls_key = args
    with open(tls_cert, "rb") as cert_obj:
        cert = x509.load_pem_x509_certificate(cert_obj.read())
    with open(tls_key, "rb") as key_obj:
        priv_key = load_pem_private_key(key_obj.read(), password=None)
    
    loop = asyncio.get_event_loop()
    coro = loop.create_server(lambda: TLSFrontend(cert, priv_key, backend_port), '127.0.0.1', frontend_port)
    server = loop.run_until_complete(coro)

    # Serve requests until Ctrl+C is pressed
    print('TLS front-end to {} running on {}'.format(backend_port, frontend_port))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    # Close the server
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()


if __name__=="__main__":
    main(sys.argv[1:])