import yaml
import base64
import re
from pwn import *

rubrics_part1 = r"""
- points: 10
  cmd: "test_getsiblings 2"
  expect: "5\n6"
  note: "[getsiblings] getsiblings failed on returning two siblings"
  name: "getsiblings - two siblings"

- points: 10
  cmd: "test_getsiblings 1"
  expect: "10"
  note: "[getsiblings] getsiblings failed on returning one sibling"
  name: "getsiblings - one sibling"

- points: 5
  cmd: "test_getsiblings 0"
  expect: ""
  note: "[getsiblings] getsiblings failed on returning zero siblings"
  name: "getsiblings - zero siblings"
"""

rubrics_part234 = r"""
- points: 30
  cmd: "test_exit_wait 1"
  expect: "1\n42\n-1\n0"
  note: "[exit and wait] first test for exit and wait failed"
  name: "exit and wait - first test"

- points: 30
  cmd: "test_exit_wait 2"
  expect: "-1\n1\n1\n0\n0\n0"
  note: "[exit and wait] second test for exit and wait failed"
  name: "exit and wait - second test"
"""

rubrics_part5 = r"""
- points: 15
  cmd: "test_waitpid"
  expect: "0 1 -1\n-1"
  note: "[waitpid] test for waitpid failed"
  name: "waitpid - test"
"""

code_test_part1 = """I2luY2x1ZGUgInR5cGVzLmgiCiNpbmNsdWRlICJ1c2VyLmgiCgppbnQgdGVzdF90d29fc2licygpIHsKICAgIGludCB3YWl0X3N0YXR1czsKCiAgICBpbnQgY2hpbGQxX3BpZCA9IGZvcmsoKTsgICAgCiAgICBpZiAoY2hpbGQxX3BpZCA9PSAwKSB7ICAgICAgICAgIAogICAgICAgIHNsZWVwKDEwMCk7ICAgICAgICAgICAgIAogICAgICAgIGdldHNpYmxpbmdzKCk7ICAgICAgICAgIAogICAgICAgIGV4aXQoMCk7ICAgICAgICAgICAgICAgIAogICAgfQoKICAgIGludCBjaGlsZDJfcGlkID0gZm9yaygpOwogICAgaWYgKGNoaWxkMl9waWQgPT0gMCkgewogICAgICAgIHNsZWVwKDEwMCk7CiAgICAgICAgZXhpdCgwKTsgICAgICAgICAgICAgICAgCiAgICB9CgogICAgaW50IGNoaWxkM19waWQgPSBmb3JrKCk7CiAgICBpZiAoY2hpbGQzX3BpZCA9PSAwKSB7CiAgICAgICAgc2xlZXAoMTAwKTsKICAgICAgICBleGl0KDApOyAgICAgICAgICAgICAgICAKICAgIH0KCiAgICB3YWl0KCZ3YWl0X3N0YXR1cyk7ICAgICAgICAgCiAgICB3YWl0KCZ3YWl0X3N0YXR1cyk7ICAgICAgICAgCiAgICB3YWl0KCZ3YWl0X3N0YXR1cyk7ICAgICAgICAKCiAgICBleGl0KDApOyAgICAgICAgICAgICAgICAgICAgCn0KCmludCB0ZXN0X29uZV9zaWJzKCkgewogICAgaW50IHdhaXRfc3RhdHVzOwoKICAgIGludCBjaGlsZF9waWQgPSBmb3JrKCk7ICAgIAogICAgaWYgKGNoaWxkX3BpZCA9PSAwKSB7ICAgICAgICAgIAogICAgICAgIHNsZWVwKDEwMCk7ICAgCgogICAgICAgIGludCBjaGlsZF9jaGlsZDFfcGlkID0gZm9yaygpOyAKICAgICAgICBpZiAoY2hpbGRfY2hpbGQxX3BpZCA9PSAwKSB7CiAgICAgICAgICAgIHNsZWVwKDEwMCk7CiAgICAgICAgICAgIGdldHNpYmxpbmdzKCk7CiAgICAgICAgICAgIGV4aXQoMCk7ICAgICAgICAgICAgICAgIAogICAgICAgIH0gCgogICAgICAgIGludCBjaGlsZF9jaGlsZDJfcGlkID0gZm9yaygpOwogICAgICAgIGlmIChjaGlsZF9jaGlsZDJfcGlkID09IDApIHsKICAgICAgICAgICAgc2xlZXAoMTAwKTsKICAgICAgICAgICAgZXhpdCgwKTsgICAgICAgICAgICAgICAgCiAgICAgICAgfSAgICAgICAgCiAgICAgICAgCiAgICAgICAgd2FpdCgmd2FpdF9zdGF0dXMpOyAgICAgICAgIAogICAgICAgIHdhaXQoJndhaXRfc3RhdHVzKTsgICAgICAgICAKICAgICAgICBleGl0KDApOyAgICAgICAgICAgICAgICAKICAgIH0KCiAgICB3YWl0KCZ3YWl0X3N0YXR1cyk7ICAgICAgICAKICAgIGV4aXQoMCk7ICAKfQoKaW50IHRlc3RfemVyb19zaWJzKCkgewogICAgaW50IHdhaXRfc3RhdHVzOwoKICAgIGludCBjaGlsZF9waWQgPSBmb3JrKCk7ICAgIAogICAgaWYgKGNoaWxkX3BpZCA9PSAwKSB7ICAgICAgICAgIAogICAgICAgIHNsZWVwKDEwMCk7ICAgCgogICAgICAgIGludCBjaGlsZF9jaGlsZDFfcGlkID0gZm9yaygpOyAKICAgICAgICBpZiAoY2hpbGRfY2hpbGQxX3BpZCA9PSAwKSB7CiAgICAgICAgICAgIHNsZWVwKDEwMCk7CgogICAgICAgICAgICBpbnQgY2hpbGRfY2hpbGRfY2hpbGQxX3BpZCA9IGZvcmsoKTsKICAgICAgICAgICAgaWYgKGNoaWxkX2NoaWxkX2NoaWxkMV9waWQgPT0gMCkgewogICAgICAgICAgICAgICAgc2xlZXAoMTAwKTsKICAgICAgICAgICAgICAgIGdldHNpYmxpbmdzKCk7CiAgICAgICAgICAgICAgICBleGl0KDApOyAgICAgICAgICAgICAgICAKICAgICAgICAgICAgfSAgICAgICAKICAgICAgICAgICAgCiAgICAgICAgICAgIHdhaXQoJndhaXRfc3RhdHVzKTsKICAgICAgICAgICAgZXhpdCgwKTsgICAgICAgICAgICAgICAgCiAgICAgICAgfSAKCiAgICAgICAgd2FpdCgmd2FpdF9zdGF0dXMpOyAgICAgICAgIAogICAgICAgIGV4aXQoMCk7ICAgICAgICAgICAgICAgIAogICAgfQoKICAgIHdhaXQoJndhaXRfc3RhdHVzKTsgICAgICAgIAogICAgZXhpdCgwKTsgICAKfQoKaW50IG1haW4oaW50IGFyZ2MsIGNoYXIgKmFyZ3ZbXSkgewogICAgaWYgKGF0b2koYXJndlsxXSkgPT0gMikgewogICAgICAgIHRlc3RfdHdvX3NpYnMoKTsgIAogICAgfSBlbHNlIGlmIChhdG9pKGFyZ3ZbMV0pID09IDEpIHsKICAgICAgICB0ZXN0X29uZV9zaWJzKCk7CiAgICB9IGVsc2UgaWYgKGF0b2koYXJndlsxXSkgPT0gMCkgewogICAgICAgIHRlc3RfemVyb19zaWJzKCk7IAogICAgfSBlbHNlIHsKICAgICAgICBwcmludGYoMSwgIlRoZSBhcmd1bWVudCBpcyBub3QgY29ycmVjdCFcbiIpOwogICAgICAgIHJldHVybiAtMTsKICAgIH0KCiAgICByZXR1cm4gMDsKfQo="""

code_test_part234 = """I2luY2x1ZGUgInR5cGVzLmgiCiNpbmNsdWRlICJzdGF0LmgiCiNpbmNsdWRlICJ1c2VyLmgiCgp2b2lkIHRlc3Rfc2ltcGxlX2V4aXRfd2FpdChpbnQgc3RhdHVzKSB7CiAgICBpbnQgcGlkID0gZm9yaygpOwogICAgaWYgKHBpZCA8IDApIHsKICAgICAgICBwcmludGYoMSwgIkZvcmsgZmFpbGVkIVxuIik7CiAgICAgICAgZXhpdCgtMSk7CiAgICB9CiAgICBpZiAocGlkID09IDApIHsKICAgICAgICBleGl0KHN0YXR1cyk7CiAgICB9IGVsc2UgewogICAgICAgIGludCB3YWl0X3N0YXR1czsKICAgICAgICBpbnQgd2FpdF9waWQgPSB3YWl0KCZ3YWl0X3N0YXR1cyk7CiAgICAgICAgaWYgKHdhaXRfcGlkID09IC0xKSB7CiAgICAgICAgICAgIHByaW50ZigxLCAiV2FpdCBmYWlsZWQhXG4iKTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgICBpZiAod2FpdF9zdGF0dXMgPT0gc3RhdHVzKSB7CiAgICAgICAgICAgICAgICBwcmludGYoMSwgIiVkXG4iLCB3YWl0X3N0YXR1cyk7CiAgICAgICAgICAgIH0KICAgICAgICB9CiAgICB9Cn0KCnZvaWQgdGVzdF9tb3JlX2V4aXRfd2FpdChpbnQgY2gxX3N0YXR1cywgaW50IGNoMl9zdGF0dXMpIHsKICAgIGludCBjaDFfcGlkID0gZm9yaygpOwogICAgaWYgKGNoMV9waWQgPCAwKSB7CiAgICAgICAgcHJpbnRmKDEsICJGb3JrIGZhaWxlZCFcbiIpOwogICAgICAgIGV4aXQoLTEpOwogICAgfQogICAgaWYgKGNoMV9waWQgPT0gMCkgewogICAgICAgIGludCBjaDJfcGlkID0gZm9yaygpOwogICAgICAgIGlmIChjaDJfcGlkIDwgMCkgewogICAgICAgICAgICBwcmludGYoMSwgIkZvcmsgZmFpbGVkIVxuIik7CiAgICAgICAgICAgIGV4aXQoLTEpOwogICAgICAgIH0KICAgICAgICBpZiAoY2gyX3BpZCA9PSAwKSB7CiAgICAgICAgICAgIC8vIHNsZWVwKDEwMCk7CiAgICAgICAgICAgIGV4aXQoY2gyX3N0YXR1cyk7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgaW50IGNoMl93YWl0X3N0YXR1czsKICAgICAgICAgICAgaW50IGNoMl93YWl0X3BpZCA9IHdhaXQoJmNoMl93YWl0X3N0YXR1cyk7CiAgICAgICAgICAgIGlmIChjaDJfd2FpdF9waWQgPT0gLTEpIHsKICAgICAgICAgICAgICAgIHByaW50ZigxLCAiV2FpdCBmYWlsZWQhXG4iKTsKICAgICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgICAgIGlmIChjaDJfd2FpdF9zdGF0dXMgPT0gY2gyX3N0YXR1cykgewogICAgICAgICAgICAgICAgICAgIHByaW50ZigxLCAiJWRcbiIsIGNoMl93YWl0X3N0YXR1cyk7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KICAgICAgICB9IAogICAgICAgIGV4aXQoY2gxX3N0YXR1cyk7CiAgICB9IGVsc2UgewogICAgICAgIGludCBjaDFfd2FpdF9zdGF0dXM7CiAgICAgICAgaW50IGNoMV93YWl0X3BpZCA9IHdhaXQoJmNoMV93YWl0X3N0YXR1cyk7CiAgICAgICAgaWYgKGNoMV93YWl0X3BpZCA9PSAtMSkgewogICAgICAgICAgICBwcmludGYoMSwgIldhaXQgZmFpbGVkIVxuIik7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgaWYgKGNoMV93YWl0X3N0YXR1cyA9PSBjaDFfc3RhdHVzKSB7CiAgICAgICAgICAgICAgICBwcmludGYoMSwgIiVkXG4iLCBjaDFfd2FpdF9zdGF0dXMpOwogICAgICAgICAgICB9CiAgICAgICAgfQogICAgfQp9Cgp2b2lkIGZpcnN0X3Rlc3QoKSB7CiAgICAvLyBUZXN0IGNhc2VzIHdpdGggZGlmZmVyZW50IGV4aXQgc3RhdHVzZXMKICAgIHRlc3Rfc2ltcGxlX2V4aXRfd2FpdCgxKTsgICAvLyBFeGl0IHdpdGggc3RhdHVzIDEKICAgIHRlc3Rfc2ltcGxlX2V4aXRfd2FpdCg0Mik7ICAvLyBFeGl0IHdpdGggc3RhdHVzIDQyCiAgICB0ZXN0X3NpbXBsZV9leGl0X3dhaXQoLTEpOyAgLy8gRXhpdCB3aXRoIHN0YXR1cyAtMQogICAgdGVzdF9zaW1wbGVfZXhpdF93YWl0KDApOyAgIC8vIE5vcm1hbCBleGl0CgogICAgZXhpdCgwKTsKfQoKdm9pZCBzZWNvbmRfdGVzdCgpIHsKICAgdGVzdF9tb3JlX2V4aXRfd2FpdCgxLCAtMSk7IAogICB0ZXN0X21vcmVfZXhpdF93YWl0KDAsIDEpOyAKICAgdGVzdF9tb3JlX2V4aXRfd2FpdCgwLCAwKTsgICAvLyBCb3RoIGV4aXQgbm9ybWFsbHkKCiAgIGV4aXQoMCk7Cn0KCmludCBtYWluKGludCBhcmdjLCBjaGFyKiBhcmd2W10pIHsKICAgIGlmIChhdG9pKGFyZ3ZbMV0pID09IDEpIHsKICAgICAgICBmaXJzdF90ZXN0KCk7ICAKICAgIH0gZWxzZSBpZiAoYXRvaShhcmd2WzFdKSA9PSAyKSB7CiAgICAgICAgc2Vjb25kX3Rlc3QoKTsKICAgIH0gZWxzZSB7CiAgICAgICAgcHJpbnRmKDEsICJUaGUgYXJndW1lbnQgaXMgbm90IGNvcnJlY3QhXG4iKTsKICAgICAgICByZXR1cm4gLTE7CiAgICB9CiAgICAKICAgIHJldHVybiAwOwp9"""

code_test_part5 = """I2luY2x1ZGUgInR5cGVzLmgiCiNpbmNsdWRlICJzdGF0LmgiCiNpbmNsdWRlICJ1c2VyLmgiCgppbnQgbWFpbih2b2lkKSB7CiAgICBpbnQgY2hpbGQxX3N0YXR1czsKICAgIGludCBjaGlsZDJfc3RhdHVzOwogICAgaW50IGNoaWxkM19zdGF0dXM7CiAgICBpbnQgb3B0aW9uczsKCiAgICBpbnQgY2hpbGQxX3BpZCA9IGZvcmsoKTsKICAgIGlmIChjaGlsZDFfcGlkIDwgMCkgewogICAgICAgIHByaW50ZigxLCAiRm9yayBmYWlsZWRcbiIpOwogICAgICAgIGV4aXQoLTEpOwogICAgfQoKICAgIGlmIChjaGlsZDFfcGlkID09IDApIHsKICAgICAgICBzbGVlcCgxMDApOwogICAgICAgIGV4aXQoMCk7IAogICAgfQoKICAgIGludCBjaGlsZDJfcGlkID0gZm9yaygpOwogICAgaWYgKGNoaWxkMl9waWQgPCAwKSB7CiAgICAgICAgcHJpbnRmKDEsICJGb3JrIGZhaWxlZFxuIik7CiAgICAgICAgZXhpdCgtMSk7CiAgICB9CgogICAgaWYgKGNoaWxkMl9waWQgPT0gMCkgewogICAgICAgIHNsZWVwKDEwMCk7CiAgICAgICAgZXhpdCgxKTsgCiAgICB9CgogICAgaW50IGNoaWxkM19waWQgPSBmb3JrKCk7CiAgICBpZiAoY2hpbGQzX3BpZCA8IDApIHsKICAgICAgICBwcmludGYoMSwgIkZvcmsgZmFpbGVkXG4iKTsKICAgICAgICBleGl0KC0xKTsKICAgIH0gCgogICAgaWYgKGNoaWxkM19waWQgPT0gMCkgewogICAgICAgIHNsZWVwKDEwMCk7CiAgICAgICAgZXhpdCgtMSk7IAogICAgfQoKICAgIC8vIFBhcmVudCBwcm9jZXNzIHdhaXRzIGZvciBzcGVjaWZpYyBjaGlsZCBwcm9jZXNzZXMKICAgIHdhaXRwaWQoY2hpbGQxX3BpZCwgJmNoaWxkMV9zdGF0dXMsIG9wdGlvbnMpOyAvLyBXYWl0IGZvciBjaGlsZCAxCiAgICB3YWl0cGlkKGNoaWxkMl9waWQsICZjaGlsZDJfc3RhdHVzLCBvcHRpb25zKTsgLy8gV2FpdCBmb3IgY2hpbGQgMgogICAgd2FpdHBpZChjaGlsZDNfcGlkLCAmY2hpbGQzX3N0YXR1cywgb3B0aW9ucyk7IC8vIFdhaXQgZm9yIGNoaWxkIDMKCiAgICBwcmludGYoMSwgIiVkICVkICVkXG4iLCBjaGlsZDFfc3RhdHVzLCBjaGlsZDJfc3RhdHVzLCBjaGlsZDNfc3RhdHVzKTsKCiAgICBpbnQgaW52YWxpZF9waWQgPSA5OTk5OwogICAgaW50IHJlc3VsdCA9IHdhaXRwaWQoaW52YWxpZF9waWQsICZjaGlsZDFfc3RhdHVzLCBvcHRpb25zKTsKICAgIHByaW50ZigxLCAiJWRcbiIsIHJlc3VsdCk7CgogICAgZXhpdCgwKTsKfQ=="""

def populate_makefile(filename):
    c = open('Makefile', 'r').read().replace(" -Werror", " ")
    uprogs = re.findall(r'UPROGS=([\w\W]*)fs\.img: mkfs', c)[0].replace("\\\n",'').split()
    uprogs.insert(0, f'_{filename}')
    uprogs = " ".join(uprogs)
    c = re.sub(r'UPROGS=([\w\W]*)fs\.img: mkfs', f'UPROGS={uprogs} \nfs.img: mkfs', c)
    open("Makefile", 'w').write(c)

def run_test(code, program, rubrics, points):
    code = base64.b64decode(code)
    populate_makefile(program)
    with open(program+".c", 'wb') as f:   
        f.write(code)

    p = process("make qemu-nox".split())

    errors = []

    try:
        p.recvuntil(b"init: starting sh\n$", timeout=10)
    except:
        print("[!] Failed to compile and start xv6 with testsuite")
        print("[!] Compile log:", p.recvall().decode('latin-1'))
        print(f"Your score: {points}")
        exit(1)

    rubrics = yaml.safe_load(rubrics)
    full = points

    for rubric in rubrics:
        print(f"[!] Checking [{rubric['name']}]")
        full += rubric["points"]
        try:
            if "cmd" in rubric:
                p.sendline(rubric["cmd"].encode())
            recv = p.recvuntil(rubric["expect"].encode(), timeout=20).decode('latin-1')
            if rubric["expect"] not in recv:
                raise Exception("Wrong output")
            points += rubric["points"]
        except:
            errors.append(rubric["note"])

    if errors:
        print("[!] Errors:")
        for error in errors:
            print("    " + error)
    else:
        print("[!] All check passed!")
    print("=======")
    print(f"Your score: {points} / {full}")

    if errors:
        exit(1)

    p.terminate()
    p.kill()

    return points

point1 = run_test(code_test_part1, "test_getsiblings", rubrics_part1, 0)
print(f"---> Your total score: {point1} / 100")
point234 = run_test(code_test_part234, "test_exit_wait", rubrics_part234, 0)
print(f"---> Your total score: {point1 + point234} / 100")
point5 = run_test(code_test_part5, "test_waitpid", rubrics_part5, 0)
print(f"---> Your total score: {point1 + point234 + point5} / 100")