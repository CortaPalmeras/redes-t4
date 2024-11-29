import random 
import sys
import os

if len(sys.argv) != 2:
    print(f"USO: {sys.orig_argv[0]} {sys.argv[0]} [size in bytes]")
    exit(1)

size = int(sys.argv[1])
for _ in range(size):
    _ = os.write(1, random.randrange(32,126).to_bytes(1))

