import random
import os
import time
from datetime import datetime
# random.seed(1)
print(random.getstate())
print(random.getstate()[1][0])
print(random.getrandbits(256))

# Check if /dev/urandom exists
urandom_exists = os.path.exists("/dev/urandom")
random_exists = os.path.exists("/dev/random")

# Temporarily set /dev/urandom to an invalid path
if urandom_exists & random_exists:
    os.rename("/dev/urandom", "/dev/urandom_temp")
    os.rename("/dev/random", "/dev/random_temp")

    print("done")

seed = time.time()
random.SystemRandom().seed(seed)
#random.SystemRandom.getstate()
#1706213689.866557
#0000000000.000001
try:
    # Attempt to use random functions
    current = datetime.now().timestamp()
    random.seed(current)
    print(random.getrandbits(256))
    print("Random above sysrand below")
    print(random.SystemRandom.getrandbits(256,256)) 
    for i in range(600):
        current = current + 0.000001
        print(random.getrandbits(256))


except NotImplementedError as e:
    print(f"Error: {e}")
finally:
    # Restore /dev/urandom if it was originally present
    if urandom_exists & random_exists:
        os.rename("/dev/urandom_temp", "/dev/urandom")
        os.rename("/dev/random_temp", "/dev/random")

        print("Done")


