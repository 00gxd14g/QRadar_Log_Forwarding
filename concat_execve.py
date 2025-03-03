#!/usr/bin/env python3
import sys
import re

for line in sys.stdin:
    line = line.strip()
    if "type=EXECVE" in line:
        # Tüm aX="değer" kısımlarını çıkar
        args = re.findall(r'a\d+="([^"]+)"', line)
        if args:
            # Argümanları boşlukla birleştir
            cmd = " ".join(args)
            # Orijinal argümanları tek bir a0="cmd" ile değiştir
            new_line = re.sub(r'(type=EXECVE.*?)( a\d+="[^"]+" )+', r'\1 a0="' + cmd + '" ', line)
            print(f"MODIFIED {new_line}")
        else:
            print("OK")
    else:
        print("OK")
