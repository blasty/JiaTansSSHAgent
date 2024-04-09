import sys
from Crypto.PublicKey import ECC
import struct

PUBKEY_ROUTINE_SIG = bytes.fromhex(
    "f30f1efa4885ff0f848e000000415455"
    "534889f34881eca00000004885f67504"
    "31c0eb6b4c8b4e084d85c974f34889e2"
    "31c0488d6c24304989fcb90c00000048"
    "89d74989e8be30000000f3abb91c0000"
    "004889eff3ab488d4c24204889d7"
)

ARGV_CHECK_ROUTINE_SIG = bytes.fromhex(
    "554889e54157415641554154534883ec"
    "2848897db84839f50f83300100004889"
    "f04889f34829e8483d00200000"
)

ARGV_PATCH_OFFSET = 0x127DE - 0x12690

COPY_KEY_CODE = bytes.fromhex(
    # lea _keybytes(%rip),%rsi
    "488d350e000000"
    # xor %rcx,%rcx
    "4831c9"
    # mov $0x39,%cl
    "b139"
    # cld
    "fc"
    # rep movsb %ds:(%rsi),%es:(%rdi)
    "f3a4"
    # mov $0x1,%eax
    "b801000000"
    # ret
    "c3"
    # _keybytes: ...
)

if __name__ == "__main__":
    if len(sys.argv) not in [4, 5]:
        print(
            "usage: %s <privkey.pem> <infile> <outfile> [patch_argv_check]\n"
            % sys.argv[0]
        )
        exit(-1)

    privkey_file, infile, outfile = sys.argv[1:4]
    patch_argv_check = len(sys.argv) == 5

    ed448_privkey = ECC.import_key(open(privkey_file).read())
    ed448_pubkey = ed448_privkey.public_key()
    ed448_pubkey_bytes = ed448_pubkey.export_key(format="raw")

    print("ed448 pubkey: %s" % ed448_pubkey_bytes.hex())

    d = bytearray(open(infile, "rb").read())

    pubkey_routine = d.find(PUBKEY_ROUTINE_SIG)
    if pubkey_routine == -1:
        print("pubkey routine not found")
        exit(-1)

    d[pubkey_routine : pubkey_routine + len(COPY_KEY_CODE)] = COPY_KEY_CODE
    d[
        pubkey_routine
        + len(COPY_KEY_CODE) : pubkey_routine
        + len(COPY_KEY_CODE)
        + len(ed448_pubkey_bytes)
    ] = ed448_pubkey_bytes

    if patch_argv_check:
        argv_check_routine = d.find(ARGV_CHECK_ROUTINE_SIG)
        if argv_check_routine == -1:
            print("argv check routine not found")
            exit(-1)

        argv_check_routine += ARGV_PATCH_OFFSET

        d[argv_check_routine : argv_check_routine + 2] = b"\xeb\xf7"

    with open(outfile, "wb") as f:
        f.write(d)

    print("patched %s -> %s" % (infile, outfile))
