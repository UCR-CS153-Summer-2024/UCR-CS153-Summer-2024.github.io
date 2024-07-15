rubrics_getsiblings = r"""
- points: 0
  cmd: "test_getsiblings"
  expect: "1"
  note: "[getsiblings] getsiblings system call failed"
  name: "getsiblings - fail"

- points: 25
  expect: "0"
  note: "[getsiblings] getsiblings system call succeeded"
  name: "getsiblings - successful"
"""

code_test_getsiblings = """I2luY2x1ZGUgInR5cGVzLmgiCiNpbmNsdWRlICJ1c2VyLmgiCgppbnQgbWFpbigpIHsKCiAgICBpbnQgY2hpbGQxX3BpZCA9IGZvcmsoKTsgICAgLy8gUGFyZW50IHByb2Nlc3MgY3JlYXRlcyB0aGUgZmlyc3QgY2hpbGQgcHJvY2VzcwogICAgaWYgKGNoaWxkMV9waWQgPT0gMCkgeyAgICAgIC8vIG1ha2Ugc3VyZSBvbmx5IHRoZSBjaGlsZCBwcm9jZXNzIGVudGVycyB0aGlzIGJsb2NrICAgICAKICAgICAgICBzbGVlcCgxMDApOyAgICAgICAgICAgICAvLyBkZWxheSB0byBhbGxvdyBzaWJpbGluZyBjcmVhdGlvbgogICAgICAgIGdldHNpYmxpbmdzKCk7ICAgICAgICAgIC8vIGdldHNpYmxpbmdzKCkgc3lzY2FsbAogICAgICAgIGV4aXQoMCk7ICAgICAgICAgICAgICAgIC8vIEV4aXQgc3RhdHVzIGFkZGVkIChsYWIxLXBhcnQzKQogICAgfQoKICAgIGludCBjaGlsZDJfcGlkID0gZm9yaygpOwogICAgaWYgKGNoaWxkMl9waWQgPT0gMCkgewogICAgICAgIHNsZWVwKDEwMCk7CiAgICAgICAgLy9nZXRzaWJsaW5ncygpOwogICAgICAgIGV4aXQoMCk7ICAgICAgICAgICAgICAgIC8vIEV4aXQgc3RhdHVzIGFkZGVkIChsYWIxLXBhcnQzKQogICAgfQoKICAgIGludCBjaGlsZDNfcGlkID0gZm9yaygpOwogICAgaWYgKGNoaWxkM19waWQgPT0gMCkgewogICAgICAgIHNsZWVwKDEwMCk7CiAgICAgICAgLy9nZXRzaWJsaW5ncygpOwogICAgICAgIGV4aXQoMCk7ICAgICAgICAgICAgICAgIC8vIEV4aXQgc3RhdHVzIGFkZGVkIChsYWIxLXBhcnQzKQogICAgfQoKICAgIC8vIENhbGxpbmcgd2FpdCBzeXNjYWxsIGVuc3VyZXMgdGhlIHBhcmVudCBwcm9jZXNzIHdhaXRzIGZvciAKICAgIC8vIGFsbCBjaGlsZCBwcm9jZXNzZXMgdG8gdGVybWluYXRlLCBwcmV2ZW50aW5nIHpvbWJpZSBwcm9jZXNzZXMuCiAgICBpbnQgd2FpdF9zdGF0dXM7CiAgICB3YWl0KCZ3YWl0X3N0YXR1cyk7ICAgICAgICAgLy8gRXhpdCBzdGF0dXMgYWRkZWQgKGxhYjEtcGFydDQpCiAgICB3YWl0KCZ3YWl0X3N0YXR1cyk7ICAgICAgICAgLy8gRXhpdCBzdGF0dXMgYWRkZWQgKGxhYjEtcGFydDQpCiAgICB3YWl0KCZ3YWl0X3N0YXR1cyk7ICAgICAgICAgLy8gRXhpdCBzdGF0dXMgYWRkZWQgKGxhYjEtcGFydDQpCgogICAgZXhpdCgwKTsgICAgICAgICAgICAgICAgICAgIC8vIEV4aXQgc3RhdHVzIGFkZGVkIChsYWIxLXBhcnQzKQp9Cg=="""

from pwn import *
import yaml
import base64
import re

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

point1 = run_test(code_test_getsiblings, "lab1_part1_getsiblings", rubrics_getsiblings, 0)
