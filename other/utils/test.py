from hashlib import sha256
import re

prefix = b'\x00' * 63

m = sha256()
m.update(prefix + b'\x02')

print(m.hexdigest())

shas = list(map(lambda x: str(int(x, 16)),
            re.findall('.{8}', m.hexdigest())))

print(" ".join(shas))
