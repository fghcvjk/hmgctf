from Crypto.Util.number import *
import gmpy2
from random import shuffle

flag = b"flag is here"


def shuffle_flag(s):
    str_list = list(s)
    shuffle(str_list)
    return ''.join(str_list)


nl = []
el = []
count = 0
while count != 5:
    p = getPrime(512)
    q = getPrime(512)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = gmpy2.next_prime(bytes_to_long(flag))
    e = gmpy2.invert(d, phi)
    nl.append(n)
    el.append(int(e))
    count += 1

print(nl)
print(el)

cl = []
flag = shuffle_flag(flag.decode()).encode()
for i in range(len(nl)):
    cl.append(pow(bytes_to_long(flag), el[i], nl[i]))
print(cl)
