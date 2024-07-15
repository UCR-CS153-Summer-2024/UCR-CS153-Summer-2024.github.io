import yaml
import base64
import re
from pwn import *

rubrics_part1 = r"""
- points: 10
  cmd: "test_getsiblings 2"
  expect: "5\n6"
  note: "[getsiblings] getsiblings succeeded on returning two siblings"
  name: "getsiblings - two siblings"

- points: 10
  cmd: "test_getsiblings 1"
  expect: "10"
  note: "[getsiblings] getsiblings succeeded on returning one sibling"
  name: "getsiblings - one sibling"

- points: 5
  cmd: "test_getsiblings 0"
  expect: ""
  note: "[getsiblings] getsiblings succeeded on returning zero siblings"
  name: "getsiblings - zero siblings"

- points: 25
  note: "[getsiblings] getsiblings failed"
  name: "getsiblings - failed"
"""

rubrics_part234 = r"""
- points: 12.5
  cmd: "test_part34 1"
  expect: "4 0"
  note: "Fork failed"
  name: "Exit & Wait - Fork first child process"

- points: 12.5
  expect: "4+0"
  note: "[Exit & Wait]Failed to obtain correct first child process exit status"
  name: "Exit & Wait - Wait for first child process"

- points: 12.5
  expect: "5 -1"
  note: "[Exit & Wait]Fork second child process failed"
  name: "Exit & Wait - Fork second child process"

- points: 12.5
  expect: "5+-1"
  note: "[Exit & Wait]Failed to obtain correct second child process exit status"
  name: "Exit & Wait - Wait for second child process"

- points: 0
  cmd: "test_part34 2"
  expect: "12 16"
  note: "[Waitpid]Failed to create 6 child processes"
  name: "Waitpid - create 6 child processes"

- points: 5
  expect: "10\n10+14+14\n8\n8+12+12\n9\n9+13+13\n7\n7+11+11\n11\n11+15+15"
  note: "[Waitpid]Child process exit status is incorrect"
  name: "Waitpid - check 5 child processes exit status"

- points: 5
  expect: "12\n-1+12+-1"
  note: "[Waitpid]Syscall does not return -1 while obtaining status of an process that's not a child of the current process"
  name: "Waitpid - check invalid process"

- points: 5
  expect: "-1"
  note: "[Waitpid]Syscall does not return -1 while obtaining status of an invalid process"
  name: "Waitpid - check invalid process"

- points: 5
  expect: "-1"
  note : "[Waitpid]Syscall does not return -1 when an invalid argument is given"
  name: "Waitpid - check invalid argument"

- points: 5
  cmd: "test_part34 3"
  expect: "-1 -1"
  note: "[Exit & Wait]Should return -1 for a child process that does not exist"
  name: "Exit & Wait - Wait for a child process that does not exist"

"""

code_test_part1 = """I2luY2x1ZGUgInR5cGVzLmgiCiNpbmNsdWRlICJ1c2VyLmgiCgppbnQgdGVzdF90d29fc2licygpIHsKICAgIGludCB3YWl0X3N0YXR1czsKCiAgICBpbnQgY2hpbGQxX3BpZCA9IGZvcmsoKTsgICAgCiAgICBpZiAoY2hpbGQxX3BpZCA9PSAwKSB7ICAgICAgICAgIAogICAgICAgIHNsZWVwKDEwMCk7ICAgICAgICAgICAgIAogICAgICAgIGdldHNpYmxpbmdzKCk7ICAgICAgICAgIAogICAgICAgIGV4aXQoMCk7ICAgICAgICAgICAgICAgIAogICAgfQoKICAgIGludCBjaGlsZDJfcGlkID0gZm9yaygpOwogICAgaWYgKGNoaWxkMl9waWQgPT0gMCkgewogICAgICAgIHNsZWVwKDEwMCk7CiAgICAgICAgZXhpdCgwKTsgICAgICAgICAgICAgICAgCiAgICB9CgogICAgaW50IGNoaWxkM19waWQgPSBmb3JrKCk7CiAgICBpZiAoY2hpbGQzX3BpZCA9PSAwKSB7CiAgICAgICAgc2xlZXAoMTAwKTsKICAgICAgICBleGl0KDApOyAgICAgICAgICAgICAgICAKICAgIH0KCiAgICB3YWl0KCZ3YWl0X3N0YXR1cyk7ICAgICAgICAgCiAgICB3YWl0KCZ3YWl0X3N0YXR1cyk7ICAgICAgICAgCiAgICB3YWl0KCZ3YWl0X3N0YXR1cyk7ICAgICAgICAKCiAgICBleGl0KDApOyAgICAgICAgICAgICAgICAgICAgCn0KCmludCB0ZXN0X29uZV9zaWJzKCkgewogICAgaW50IHdhaXRfc3RhdHVzOwoKICAgIGludCBjaGlsZF9waWQgPSBmb3JrKCk7ICAgIAogICAgaWYgKGNoaWxkX3BpZCA9PSAwKSB7ICAgICAgICAgIAogICAgICAgIHNsZWVwKDEwMCk7ICAgCgogICAgICAgIGludCBjaGlsZF9jaGlsZDFfcGlkID0gZm9yaygpOyAKICAgICAgICBpZiAoY2hpbGRfY2hpbGQxX3BpZCA9PSAwKSB7CiAgICAgICAgICAgIHNsZWVwKDEwMCk7CiAgICAgICAgICAgIGdldHNpYmxpbmdzKCk7CiAgICAgICAgICAgIGV4aXQoMCk7ICAgICAgICAgICAgICAgIAogICAgICAgIH0gCgogICAgICAgIGludCBjaGlsZF9jaGlsZDJfcGlkID0gZm9yaygpOwogICAgICAgIGlmIChjaGlsZF9jaGlsZDJfcGlkID09IDApIHsKICAgICAgICAgICAgc2xlZXAoMTAwKTsKICAgICAgICAgICAgZXhpdCgwKTsgICAgICAgICAgICAgICAgCiAgICAgICAgfSAgICAgICAgCiAgICAgICAgCiAgICAgICAgd2FpdCgmd2FpdF9zdGF0dXMpOyAgICAgICAgIAogICAgICAgIHdhaXQoJndhaXRfc3RhdHVzKTsgICAgICAgICAKICAgICAgICBleGl0KDApOyAgICAgICAgICAgICAgICAKICAgIH0KCiAgICB3YWl0KCZ3YWl0X3N0YXR1cyk7ICAgICAgICAKICAgIGV4aXQoMCk7ICAKfQoKaW50IHRlc3RfemVyb19zaWJzKCkgewogICAgaW50IHdhaXRfc3RhdHVzOwoKICAgIGludCBjaGlsZF9waWQgPSBmb3JrKCk7ICAgIAogICAgaWYgKGNoaWxkX3BpZCA9PSAwKSB7ICAgICAgICAgIAogICAgICAgIHNsZWVwKDEwMCk7ICAgCgogICAgICAgIGludCBjaGlsZF9jaGlsZDFfcGlkID0gZm9yaygpOyAKICAgICAgICBpZiAoY2hpbGRfY2hpbGQxX3BpZCA9PSAwKSB7CiAgICAgICAgICAgIHNsZWVwKDEwMCk7CgogICAgICAgICAgICBpbnQgY2hpbGRfY2hpbGRfY2hpbGQxX3BpZCA9IGZvcmsoKTsKICAgICAgICAgICAgaWYgKGNoaWxkX2NoaWxkX2NoaWxkMV9waWQgPT0gMCkgewogICAgICAgICAgICAgICAgc2xlZXAoMTAwKTsKICAgICAgICAgICAgICAgIGdldHNpYmxpbmdzKCk7CiAgICAgICAgICAgICAgICBleGl0KDApOyAgICAgICAgICAgICAgICAKICAgICAgICAgICAgfSAgICAgICAKICAgICAgICAgICAgCiAgICAgICAgICAgIHdhaXQoJndhaXRfc3RhdHVzKTsKICAgICAgICAgICAgZXhpdCgwKTsgICAgICAgICAgICAgICAgCiAgICAgICAgfSAKCiAgICAgICAgd2FpdCgmd2FpdF9zdGF0dXMpOyAgICAgICAgIAogICAgICAgIGV4aXQoMCk7ICAgICAgICAgICAgICAgIAogICAgfQoKICAgIHdhaXQoJndhaXRfc3RhdHVzKTsgICAgICAgIAogICAgZXhpdCgwKTsgICAKfQoKaW50IG1haW4oaW50IGFyZ2MsIGNoYXIgKmFyZ3ZbXSkgewogICAgaWYgKGF0b2koYXJndlsxXSkgPT0gMikgewogICAgICAgIHRlc3RfdHdvX3NpYnMoKTsgIAogICAgfSBlbHNlIGlmIChhdG9pKGFyZ3ZbMV0pID09IDEpIHsKICAgICAgICB0ZXN0X29uZV9zaWJzKCk7CiAgICB9IGVsc2UgaWYgKGF0b2koYXJndlsxXSkgPT0gMCkgewogICAgICAgIHRlc3RfemVyb19zaWJzKCk7IAogICAgfSBlbHNlIHsKICAgICAgICBwcmludGYoMSwgIlRoZSBhcmd1bWVudCBpcyBub3QgY29ycmVjdCFcbiIpOwogICAgICAgIHJldHVybiAtMTsKICAgIH0KCiAgICByZXR1cm4gMDsKfQo="""

code_test_part34 = """"I2luY2x1ZGUgInR5cGVzLmgiCiNpbmNsdWRlICJ1c2VyLmgiCgppbnQgbWFpbihpbnQgYXJnYywgY2hhciAqYXJndltdKQp7CiAgICBpbnQgZXhpdFdhaXQodm9pZCk7CiAgICBpbnQgd2FpdE5vdGhpbmcodm9pZCk7CgogICAgcHJpbnRmKDEsICJcbmxhYiMxXG4iKTsKICAgIGlmIChhdG9pKGFyZ3ZbMV0pID09IDEpCiAgICAgICAgZXhpdFdhaXQoKTsgIAogICAgZWxzZSBpZiAoYXRvaShhcmd2WzFdKSA9PSAyKQogICAgICAgIHdhaXROb3RoaW5nKCk7CiAgICAvLyBFbmQgb2YgdGVzdAogICAgLy8gZXhpdCgwKTsKICAgIHJldHVybiAwOwp9CgoKaW50IHdhaXROb3RoaW5nKHZvaWQpewogICAgaW50IHJldCwgZXhpdF9zdGF0dXMgPSAtMTsKICAgIHJldCA9IHdhaXQoJmV4aXRfc3RhdHVzKTsKICAgIHByaW50ZigxLCAiJWQgJWRcbiIsIHJldCwgZXhpdF9zdGF0dXMpOwogICAgcmV0dXJuIDA7Cn0KCmludCBleGl0V2FpdCh2b2lkKSB7CiAgICBpbnQgcGlkLCByZXRfcGlkLCBleGl0X3N0YXR1czsKICAgIGludCBpOwoKICAgIGZvciAoaSA9IDA7IGkgPCAyOyBpKyspIHsKICAgICAgICBwaWQgPSBmb3JrKCk7CiAgICAgICAgaWYgKHBpZCA9PSAwKSB7IC8vIG9ubHkgdGhlIGNoaWxkIGV4ZWN1dGVkIHRoaXMgY29kZQogICAgICAgICAgICBpZiAoaSA9PSAwKXsKICAgICAgICAgICAgICAgIHByaW50ZigxLCAiJWQgJWRcbiIsIGdldHBpZCgpLCAwKTsKICAgICAgICAgICAgICAgIGV4aXQoMCk7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgZWxzZXsKICAgICAgICAgICAgICAgIHByaW50ZigxLCAiJWQgJWRcbiIgLGdldHBpZCgpLCAtMSk7CiAgICAgICAgICAgICAgICBleGl0KC0xKTsKICAgICAgICAgICAgfSAKICAgICAgICB9IGVsc2UgaWYgKHBpZCA+IDApIHsgLy8gb25seSB0aGUgcGFyZW50IGV4ZWN1dGVzIHRoaXMgY29kZQogICAgICAgICAgICByZXRfcGlkID0gd2FpdCgmZXhpdF9zdGF0dXMpOwogICAgICAgICAgICBwcmludGYoMSwgIiVkKyVkXG4iLCByZXRfcGlkLCBleGl0X3N0YXR1cyk7CiAgICAgICAgfSBlbHNlIHsgLy8gc29tZXRoaW5nIHdlbnQgd3Jvbmcgd2l0aCBmb3JrIHN5c3RlbSBjYWxsCiAgICAgICAgICAgIHByaW50ZigyLCAiXG5FcnJvciB1c2luZyBmb3JrXG4iKTsKICAgICAgICAgICAgZXhpdCgtMSk7CiAgICAgICAgfQogICAgfQogICAgcmV0dXJuIDA7Cn0="""

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
            recv = p.recvuntil(rubric["expect"].encode(), timeout=2).decode('latin-1')
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
# point34 = run_test(code_test_part34, "lab1_part34", rubrics_part34, 0)
