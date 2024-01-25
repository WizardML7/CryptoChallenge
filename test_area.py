import random
import os
import time

# Check if /dev/urandom exists
urandom_exists = os.path.exists("/dev/urandom")
random_exists = os.path.exists("/dev/random")

# Temporarily set /dev/urandom to an invalid path
if urandom_exists & random_exists:
    os.rename("/dev/urandom", "/dev/urandom_temp")
    os.rename("/dev/random", "/dev/random_temp")

    print("done")

seed = time.time()
r1 = random.SystemRandom(seed)

try:
    # Attempt to use random functions
    for i in range(10):
        print(r1.getrandbits(256)) 
except NotImplementedError as e:
    print(f"Error: {e}")
finally:
    # Restore /dev/urandom if it was originally present
    if urandom_exists & random_exists:
        os.rename("/dev/urandom_temp", "/dev/urandom")
        os.rename("/dev/random_temp", "/dev/random")

        print("Done")


