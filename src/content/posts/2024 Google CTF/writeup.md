
---
title: 2024 Google CTF writeup
published: 2024-06-24
description: 2 solve
tags: [DES]
category: Crypto
draft: false
---

# 2024 GOOGLE CTF
기말고사 기간이라 ~~열심히 공부하다~~ 잠깐 했다

## DISFUNCTONAL
### source code
```python
import signal
import os
import random
import sys
from Crypto.Cipher import DES3

class Desfunctional:
    def __init__(self):
        self.key = os.urandom(24)
        self.iv = os.urandom(8)
        self.flipped_bits = set(range(0, 192, 8))
        self.challenge = os.urandom(64)
        self.counter = 128

    def get_flag(self, plain):
        if plain == self.challenge:
            with open("flag.txt", "rb") as f:
                FLAG = f.read()
            return FLAG
        raise Exception("Not quite right")

    def get_challenge(self):
        cipher = DES3.new(self.key, mode=DES3.MODE_CBC, iv=self.iv)
        return cipher.encrypt(self.challenge)

    def corruption(self):
        if len(self.flipped_bits) == 192:
            self.flipped_bits = set(range(0, 192, 8))
        remaining = list(set(range(192)) - self.flipped_bits)
        num_flips = random.randint(1, len(remaining))
        self.flipped_bits = self.flipped_bits.union(
            random.choices(remaining, k=num_flips))
        mask = int.to_bytes(sum(2**i for i in self.flipped_bits), 24)
        return bytes(i ^ j for i, j in zip(self.key, mask))

    def decrypt(self, text: bytes):
        self.counter -= 1
        if self.counter < 0:
            raise Exception("Out of balance")
        key = self.corruption()
        if len(text) % 8 != 0:
            return b''
        cipher = DES3.new(key, mode=DES3.MODE_CBC, iv=self.iv)
        return cipher.decrypt(text)


if __name__ == "__main__":
    chall = Desfunctional()
    PROMPT = ("Choose an API option\n"
              "1. Get challenge\n"
              "2. Decrypt\n"
              "3. Get the flag\n")
    signal.alarm(128)
    while True:
        try:
            option = int(input(PROMPT))
            if option == 1:
                print(chall.get_challenge().hex())
            elif option == 2:
                ct = bytes.fromhex(input("(hex) ct: "))
                print(chall.decrypt(ct).hex())
            elif option == 3:
                pt = bytes.fromhex(input("(hex) pt: "))
                print(chall.get_flag(pt))
                sys.exit(0)
        except Exception as e:
            print(e)
            sys.exit(1)
```
`key`로 encrypt 된 `challenge`를 얻을 수 있고, `key`의 일부 비트가 반전된 `key'`로 임의의 값을 decrypt할 수 있다.<br>
`corruption`함수를 관찰해본 결과, 평균 9번 정도 실행할 경우 `mask = b'\xff'*24`가 된다.<br>

`key' = key ^ mask`로 여러 값들을 decrypt하고, mask와 xor 한 값들을 관찰한 결과

::: note[important]
chall         = 3e6076df89cf1d5bdf30a22177f891c99099d47aaf1e28cd0291f876e5c9da38ffef568b7808cd8fcff914e9ccac8fc94017b3bcd54743ae14b72209785bef0a<br>
$E_{key}$(chall)               = 851cba77dd6d0415ba2cd9600ae3adbef9d163a7cf1ac398e3c68a820c51379512dcc8667b9384be0b0d7db26e70da106af87a793a2097f09263fd5616166c56<br>
$E_{key}$(chall) $\bigoplus$ mask           = 7ae345882292fbea45d3269ff51c5241062e9c5830e53c671c39757df3aec86aed233799846c7b41f4f2824d918f25ef95078586c5df680f6d9c02a9e9e993a9<br>
$D_{key'}$(enc $\bigoplus$ mask)      = c19f89207630e2a4df30a22177f891c99099d47aaf1e28cd0291f876e5c9da38ffef568b7808cd8fcff914e9ccac8fc94017b3bcd54743ae14b72209785bef0a<br>
$D_{key'}$(enc $\bigoplus$ mask) $\bigoplus$ mask = 3e6076df89cf1d5b20cf5dde88076e366f662b8550e1d732fd6e07891a3625c70010a97487f732703006eb1633537036bfe84c432ab8bc51eb48ddf687a410f5
`challenge = dec(enc^mask)^mask[:8]+dec(enc^mask)[8:]`
:::
### exploit
```python
from pwn import *
from tqdm import tqdm

context.log_level = 'error'

while True:
    p = remote("desfunctional.2024.ctfcompetition.com", 1337)

    p.sendlineafter(b"flag\n", b"1")
    enc = bytes.fromhex(p.recvline(keepends=False).decode())
    enc = xor(enc, b'\xff'*64)

    for _ in tqdm(range(9)):
        p.sendlineafter(b"flag\n", b"2")
        p.sendlineafter(b"ct: ", enc.hex().encode())
        dec = bytes.fromhex(p.recvline(keepends=False).decode())

    p.sendlineafter(b"flag\n", b"3")
    chall = xor(dec[:8], b'\xff'*8) + dec[8:]
    p.sendlineafter(b"pt: ", chall.hex().encode())

    flag = p.recvline()
    if flag.find(b"CTF") != -1: 
        import re
        flag = re.search('CTF{.*}', flag.decode()).group()
        raise ZeroDivisionError(flag)    
```
> `CTF{y0u_m4y_NOT_g3t_th3_k3y_but_y0u_m4y_NOT_g3t_th3_c1ph3rt3xt_as_w3ll}`

## BLINDERS
### source code
```python
from ecdsa.curves import NIST256p
from ecdsa.numbertheory import jacobi, square_root_mod_prime
from ecdsa.ellipticcurve import Point
from Crypto.Random import random
import hashlib

curve = NIST256p.curve

def H(id):
    a, b, p = curve.a(), curve.b(), curve.p()

    hash = hashlib.sha256(f'id={id}'.encode()).digest()
    x = int.from_bytes(hash, 'big')

    while True:
        y2 = (x**3 + a*x + b) % p
        if jacobi(y2, p) == 1: break
        x += 1

    y = square_root_mod_prime(y2, p)
    return Point(curve, x, y)

# Implements Blinders, a private set membership protocol.
class BlindersServer:
    def __init__(self, S):
        self.S = S
    
    def handle(self, client_eid):
        # 2.1. Generate a random secret key k
        k = random.randrange(0, NIST256p.order)
        # Compute eid1 = H(id1)^K, ..., eidn = H(idn)^K
        eids = [H(id) * k for id in self.S]
        # Compute doubly-encrypted identifier deid = eid^K
        deid = client_eid * k
        # Return (eid1, ..., eidn) and deid to P1
        return eids, deid

def challenge():
    # S = {0, 1, ..., 255} \ {x} for some 0 <= x < 256
    S = list(range(256))
    S.remove(random.getrandbits(8))
    server = BlindersServer(S)

    for _ in range(3):
        operation, *params = input().split()
        if operation == 'handle':
            client_eid = Point(curve, int(params[0]), int(params[1]))
            eids, deid = server.handle(client_eid)
            print([(eid.x(), eid.y()) for eid in eids])
            print((deid.x(), deid.y()))
        elif operation == 'submit':
            client_S_hash = bytes.fromhex(params[0])
            S_hash = hashlib.sha256(','.join(map(str, server.S)).encode()).digest()
            return client_S_hash == S_hash
        else:
            return False

if __name__ == '__main__':
    with open('/flag.txt', 'r') as f:
        FLAG = f.read().strip()

    # Convince me 16 times and I will give you the flag :)
    for _ in range(16):
        if challenge():
            print('OK!')
        else:
            print('Nope.')
            break
    else:
        print(FLAG)
```
`eids` = 0부터 255 사이의 정수 중 하나를 제외한 배열<br>
`x = [bytes_to_long(sha256("id={id}").digest()) for id in eids]`의 x좌표 255개의 대해 각각 `secp256r1 curve`위의 point 255개를 생성한다.<br>
그 후 [0, `curve order`) 사이 난수 `K`에 대해 `[K*point for point in Points]`, 우리가 입력한 point `deid`에 대해 `K*deid`를 알 수 있다.

^학교 끝나고 이어서 쓰기