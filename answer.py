import requests
import zlib
import base64
import wave
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import time
import random
import hmac
import hashlib
import os
import struct
from decimal import Decimal, getcontext
#import hashpumpy

# Global values
base = "http://crypto.praetorian.com/{}"
email = "dml3483@g.rit.edu"
auth_token = None

# Used for authentication
def token(email):
	global auth_token
	if not auth_token:
		url = base.format("api-token-auth/")
		resp = requests.post(url, data={"email":email})
		auth_token = {"Authorization":"JWT " + resp.json()['token']}
		resp.close()
	return auth_token

# Fetch the challenge and hint for level n
def fetch(n):
	url = base.format("challenge/{}/".format(n))
	resp = requests.get(url, headers=token(email))
	resp.close()
	if resp.status_code != 200:
		raise Exception(resp.json()['detail'])
	
	print(resp.json())
	return resp.json()

# Submit a guess for level n
def solve(n, guess):
	url = base.format("challenge/{}/".format(n))
	data = {"guess": guess}
	resp = requests.post(url, headers=token(email), data=data)
	resp.close()
	if resp.status_code != 200:
		raise Exception(resp.json()['detail'])
	return resp.json()


def caesarCipher(ciphertext):
    decrypted_text = ""
    for char in ciphertext:
        if char.isalpha():
            # Determine whether the character is uppercase or lowercase
            is_upper = char.isupper()
                
            # Apply the Caesar cipher decryption
            decrypted_char = chr((ord(char) - 23 - ord('A' if is_upper else 'a')) % 26 + ord('A' if is_upper else 'a'))

            decrypted_text += decrypted_char
        else:
            decrypted_text += char
        
    return decrypted_text

def extract_pixel_data(base64_encoded_png):
    try:
        # Ensure correct Base64 padding
        padding = len(base64_encoded_png) % 4
        base64_encoded_png += b'=' * (4 - padding)

        # print("LOOK HERE \n")
        # print(base64_encoded_png)

        # Decode Base64
        binary_png = base64.b64decode(base64_encoded_png)

        # Find the start and end positions of IDAT and IEND chunks
        idat_start = binary_png.find(b'\x49\x44\x41\x54')  # IDAT chunk
        iend_start = binary_png.find(b'\x49\x45\x4E\x44')  # IEND chunk

        if idat_start == -1 or iend_start == -1:
            print("IDAT or IEND chunk not found.")
            return None

        # Extract data between IDAT and IEND
        compressed_data = binary_png[idat_start + 4:iend_start]

        # Decompress the data
        decompressed_data = zlib.decompress(compressed_data)

        # print("THIS IS THE DECOMPRESSED DATA: \n")

        # print(decompressed_data)

        return decompressed_data
    except (base64.binascii.Error, zlib.error) as e:
        print("Error:", e)
        return None

def extract_message_from_pixel_data(pixel_data):
    try:
        message_bits = []

        # Iterate through each byte in the pixel data
        for byte in pixel_data:
            # Extract all 8 bits from each byte
            for i in range(7, -1, -1):
                # Extract the i-th bit and append to the message_bits list
                message_bits.append((byte >> i) & 1)

        # Convert the list of bits to bytes
        message_bytes = bytearray()
        for i in range(0, len(message_bits), 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | message_bits[i + j]
            message_bytes.append(byte)

        # Convert the bytes to a string (assuming the message is ASCII characters)
        message = message_bytes.decode('ascii', errors='replace')

        print(message)

        return message
    except UnicodeDecodeError as e:
        print("Error decoding message:", e)
        return None

def plot_audio_spectrum(wav_file_path, time_range=None, frequency_range=None, nfft=1024, cmap='viridis'):
    # Open the WAV file
    with wave.open(wav_file_path, 'rb') as wav_file:
        # Get the audio sample rate and number of frames
        sample_rate = wav_file.getframerate()
        num_frames = wav_file.getnframes()

        # Read all frames
        frames = wav_file.readframes(num_frames)

    # Convert frames to a NumPy array of samples
    samples = np.frombuffer(frames, dtype=np.uint8)  # Use uint8 for 8 bits per sample

    # Plot the spectrum of the audio file with adjusted parameters
    plt.figure(figsize=(10, 4))
    plt.specgram(samples, NFFT=nfft, Fs=sample_rate, cmap=cmap)
    plt.xlabel('Time (s)')
    plt.ylabel('Frequency (Hz)')
    plt.title('Spectrogram of the Audio File')

    # Set x-axis limits based on the specified time range
    if time_range:
        plt.xlim(time_range)

    # Set y-axis limits based on the specified frequency range
    if frequency_range:
        plt.ylim(frequency_range)

    plt.show()

def guess_time_measure(starting_letter,starting_time):
    time.sleep(.5)
    the_word = starting_letter
    current_time = starting_time
    count = 0
    max_time_diff = 0
    while True:
        best_letter = ""
        for letter_ascii in range(ord('a'), ord('z')+1):
            count += 1
            current_guess = the_word + chr(letter_ascii)
            start = datetime.now()
            h = solve(level, current_guess)
            end = datetime.now()
            total_time = (end - start).total_seconds()
            time_diff = total_time - current_time
            # print("The current word: " + current_guess)
            # print(time_diff)
            # print()

            if time_diff > max_time_diff:
                max_time_diff = time_diff
                best_letter = chr(letter_ascii)
            

            if count % 26 == 0:
                the_word += best_letter
                # print(the_word)
                max_time_diff = 0
                    # next_letter = input("Enter in next letter here: ")
                    # if next_letter != "1":  
                    #     the_word += next_letter
                    #     print(the_word)

            # if 0.05 <= time_diff <= 0.14:
            #     the_word += chr(letter_ascii)
            #     current_time = total_time
            #     continue
            time.sleep(.5)

        print(the_word)

        continue_with_word = input("Input 0 to continue with word and 1 to skip: ")

        if continue_with_word == "1":
            break

        print()

        zero_or_one = input("Input 0 to search capital letters and 1 to skip: ")

        # zero_or_one = "1"

        if zero_or_one == "0":
            for letter_ascii in range(ord('A'), ord('Z')+1):
                recursive_starting_letter = the_word + chr(letter_ascii)
                start = datetime.now()
                h = solve(level, recursive_starting_letter)
                end = datetime.now()
                total_time = (end - start).total_seconds()
                guess_time_measure(recursive_starting_letter,total_time)

                # count += 1
                # current_guess = the_word + chr(letter_ascii)
                # start = datetime.now()
                # h = solve(level, current_guess)
                # end = datetime.now()
                # time_diff = total_time - current_time
                # print("The current word: " + current_guess)
                # print(time_diff)
                # print()

                # if time_diff > max_time_diff:
                #     max_time_diff = time_diff
                #     best_letter = chr(letter_ascii)

                # if count % 26 == 0:
                #     the_word += best_letter
                #     print(the_word)
                #     max_time_diff = 0
                #     # next_letter = input("Enter in next letter here: ")
                #     # if next_letter != "1": 
                #     #     the_word += next_letter
                #     #     print(the_word)

                # # if 0.05 <= time_diff <= 0.14:
                # #     the_word += chr(letter_ascii)
                # #     current_time = total_time
                # #     continue
                # time.sleep(.5)
             
        if 'hash' in h: 
            hashes[level] = h['hash']
            break

def xor_hex_strings(hex_str1, hex_str2):
    # Convert hexadecimal strings to integers
    int_val1 = int(hex_str1, 16)
    int_val2 = int(hex_str2, 16)

    # Perform XOR operation
    result_int = int_val1 ^ int_val2

    # Convert the result back to a hexadecimal string
    result_hex_str = hex(result_int)[2:]

    # Ensure the result has the correct length (padding with zeros if needed)
    result_hex_str = result_hex_str.zfill(len(hex_str1))

    return result_hex_str

# def md5_length_extension_attack(original_message, known_hash_value, appended_data):
#     # Known length of the original message
#     original_length = len(original_message)

#     # Construct the padding for the original message
#     padding = b'\x80' + b'\x00' * ((64 - (original_length + 9) % 64) % 64)

#     # Append the length of the original message (in bits) to the padding
#     padded_message = original_message + padding + (original_length * 8).to_bytes(8, 'little')

#     #Calculate the HMAC using the known hash value as the key
#     hmac_obj = hmac.new(known_hash_value, msg=padded_message, digestmod=hashlib.md5)

#     # Continue hashing with the appended data
#     hmac_obj.update(appended_data.encode('utf-8'))

#     # Obtain the final hash value
#     new_hash_value = hmac_obj.hexdigest()

#     return new_hash_value

def sha1_length_extension_attack(original_message, known_hash_value, appended_data):
    # Known length of the original message
    original_length = len(original_message)

    # Construct the padding for the original message
    padding = b'\x80' + b'\x00' * ((64 - (original_length + 9) % 64) % 64)

    # Append the length of the original message (in bits) to the padding
    padded_message = original_message + padding + (original_length * 8).to_bytes(8, 'big')

    # Calculate the HMAC using the known hash value as the key
    hmac_obj = hmac.new(known_hash_value, msg=padded_message, digestmod=hashlib.sha1)

    # Continue hashing with the appended data
    hmac_obj.update(appended_data)

    # Obtain the final hash value
    new_hash_value = hmac_obj.digest()

    return new_hash_value

def sha256_length_extension_attack(original_message, known_hmac, appended_data):
    # Known length of the original message
    original_length = len(original_message)

    # Construct the padding for the original message
    padding = b'\x80' + b'\x00' * ((64 - (original_length + 9) % 64) % 64)

    # Append the length of the original message (in bits) to the padding
    padded_message = original_message + padding + (original_length * 8).to_bytes(8, 'big')

    # Calculate the HMAC using the known HMAC as the key
    hmac_obj = hmac.new(known_hmac, msg=padded_message, digestmod=hashlib.sha256)

    # Continue hashing with the appended data
    hmac_obj.update(appended_data)

    # Obtain the final hash value
    new_hmac = hmac_obj.digest()

    return new_hmac

def md5_brute_force(known_hmac_hex):
    count = 0
    max_iterations = 32768  # Set a maximum number of iterations

    username = "username=user00000"

    username_bytes = username.encode('utf-8')

    username_hex = username_bytes.hex()

    while count < max_iterations:
        random.seed(count)
        for i in range(0,50):

            secret_key_int = random.getrandbits(256)

            secret_key_bytes = secret_key_int.to_bytes(32, byteorder='big')

            hmac_obj = hmac.new(secret_key_bytes, username_bytes, hashlib.md5)

            # Get the HMAC digest
            digest = hmac_obj.hexdigest()
            # digest_hex = digest.hex()

            if hmac.compare_digest(digest,known_hmac_hex):
                print("Found a match")
                username = "username=admin"

                username_bytes = username.encode('utf-8')

                username_hex = username_bytes.hex()

                secret_key_int = random.getrandbits(256)

                secret_key_bytes = secret_key_int.to_bytes(32, byteorder='big')

                hmac_obj = hmac.new(secret_key_bytes, username_bytes, hashlib.md5)

                # Get the HMAC digest
                digest = hmac_obj.digest()
                digest_hex = digest.hex()

                guess = username_hex + ":"

                guess += digest_hex

                h = solve(level, guess)
                if 'hash' in h: hashes[level] = h['hash']
        count += 1

def predict_next_key(hmac_hexdigest, message, key_size):
    # Attempt to predict the next key based on the known HMAC hexdigest
    known_hmac = bytes.fromhex(hmac_hexdigest)
    known_message = message.encode()

    for potential_key in range(2 ** key_size):
        potential_key_bytes = potential_key.to_bytes((key_size + 7) // 8, byteorder='big')
        potential_hmac = hmac.new(potential_key_bytes, known_message, hashlib.md5).hexdigest()

        if potential_hmac == known_hmac:
            return potential_key

    return None

def precise_seed_from_time(base_time, target_time):
    base_seconds = base_time.timestamp()
    target_seconds = target_time.timestamp()
    ns_offset = (target_seconds - base_seconds) * 1e9
    seed = base_seconds + (ns_offset / 1e9)
    return seed

def sys_time_MD5_brute_force_precise_ns(start_time, end_time, known_hmac_hex):
    base_time = start_time  # Using start_time as the base for offsets
    current_time = start_time

    username = "username=user00000"
    username_bytes = username.encode('utf-8')

    while current_time <= end_time:
        seed = precise_seed_from_time(base_time, current_time)
        random.seed(seed)
        print(seed)

        secret_key_int = random.getrandbits(256)
        secret_key_bytes = secret_key_int.to_bytes(32, byteorder='big')

        hmac_obj = hmac.new(secret_key_bytes, username_bytes, hashlib.md5)
        digest = hmac_obj.hexdigest()

        if known_hmac_hex in digest:
            print(f"Found a match at seed time: {current_time}")
            admin_username = "username=admin"
            admin_username_bytes = admin_username.encode('utf-8')
            admin_hmac_obj = hmac.new(secret_key_bytes, admin_username_bytes, hashlib.md5)
            admin_digest = admin_hmac_obj.hexdigest()

            guess = f"{admin_username_bytes.hex()}:{admin_digest}"
            print(f"Submit this guess: {guess}")
            break
        else:
            # Increment the current time by one nanosecond
            current_time += timedelta(microseconds=1)



def iterate_hex_string(target_length):
    """
    Generate hexadecimal strings of a specified length. The function starts with
    a string of all '1's and modifies it left to right, incrementing each character.
    """
    # Initialize the string with all '0's
    hex_string = '0' * target_length

    # Convert the string to a list of integers for easy manipulation
    int_list = [int(char, 16) for char in hex_string]

    # Function to increment the integer list
    def increment_list(int_list):
        for i in range(len(int_list)):
            if int_list[i] < 15:  # If less than 'f', simply increment
                int_list[i] += 1
                break
            else:  # If 'f', set to '0' and continue to the next character
                int_list[i] = 0

    while True:
        # Yield the current hex string
        yield ''.join(hex(char) for char in int_list).replace('0x', '')

        # Increment the list
        increment_list(int_list)


hashes = {}

for i in range(7, 8):
    level = i
    start_time = datetime.now() - timedelta(seconds=.5)
    #current_time = str(time.time()).encode('utf-8')
    data = fetch(level)
    end_time = datetime.now()
    # print(start_time)
    # print(end_time)
    # data = 'hi'

    if level == 0:
        guess = data['challenge']
        h = solve(level, guess)
        if 'hash' in h: hashes[level] = h['hash']
    elif level == 1:
        guess = caesarCipher(data['challenge'])
        h = solve(level, guess)
        if 'hash' in h: hashes[level] = h['hash']
    elif level == 2:
        guess = input("Input guess here: ")
        h = solve(level, guess)
        if 'hash' in h: hashes[level] = h['hash']
    elif level == 3:
        guess = data['challenge']
        guess = guess[22:]
        guess = guess.encode("utf-8")
        guess = extract_pixel_data(guess)
        guess = extract_message_from_pixel_data(guess)
        guess = input("Give the guess here: ")
        h = solve(level, guess)
        if 'hash' in h: hashes[level] = h['hash']
    elif level == 4:
        guess = input("Input guess here: ")
        h = solve(level, guess)
        # url = "http://crypto.praetorian.com/static/files/hint4.py"
        # resp = requests.get(url, headers=token(email))
        # resp.close()
        # print(resp.content)
        if 'hash' in h: hashes[level] = h['hash']
    elif level == 5:
        challenge_text = data['challenge']
        file_path = "challenge_text.txt"
        with open(file_path, 'w') as file:
            file.write(challenge_text)
        with open("challenge_text.txt", "r") as file:
            encoded_wav_data = file.read()[22:]
        # Decode the base64 data
        decoded_wav_data = base64.b64decode(encoded_wav_data)

        output_wav_path = "output.wav"
        with open(output_wav_path, "wb") as wav_file:
            wav_file.write(decoded_wav_data)

        plot_audio_spectrum(output_wav_path, time_range=(0, 27), frequency_range=(14500, 16000))  # Adjust the ranges as neede
        guess = input("Put guess here: ")
        h = solve(level, guess)
        if 'hash' in h: hashes[level] = h['hash']
    elif level == 6:
        starting_letter = input("Put starting_letter here: ")
        start = datetime.now()
        h = solve(level, starting_letter)
        end = datetime.now()
        total_time = (end - start).total_seconds()
        print(total_time)


        guess_time_measure(starting_letter,total_time)

    elif level == 7:
        # {'challenge': 'I need to be an admin...
        #  Submissions should be in the following form:
        #  {"guess": hex(msg)+":"+mac(msg)}
        # {"guess": "757365726e616d653d757365723030303030:07589ba60627603552d929e6b15a1227"}
        #  HMAC(256-bit-key, \'username=user00000\') = 07589ba60627603552d929e6b15a1227', 
        # 'hint': 'NotImplementedError: /dev/urandom (or equivalent) not found... 
        #  key = random.getrandbits(256)...', 'level': '7'}

        # 433eff06bce3f22b8c97ff26e9023601190b369f
        # 07589ba60627603552d929e6b15a1227
        # 5dd4161c0a71075d846e13e049d5726a

        #dd if=/dev/random bs=1 count=1
        #dd if=/dev/urandom bs=1 count=1 | od -cx

        # known_hmac = bytes.fromhex(known_hmac_hex)data['challenge'][152:184]

        known_hmac_hex = data['challenge'][152:184]
        known_hash_value = bytes.fromhex(known_hmac_hex)
        print(known_hmac_hex)
        # print(int(start_time))
        # end_time = end_time
        # print(int(end_time))

        # # Check if /dev/urandom exists
        # urandom_exists = os.path.exists("/dev/urandom")
        # random_exists = os.path.exists("/dev/random")

        # if urandom_exists & random_exists:
        #     os.rename("/dev/urandom", "/dev/urandom_temp")
        #     os.rename("/dev/random", "/dev/random_temp")

        #     print("done")

        # random.seed(time.time_ns())
        # secret_key_int = random.getrandbits(256)

        # secret_key_bytes = secret_key_int.to_bytes(32, byteorder='big')

        # username = "username=admin"

        # username_bytes = username.encode('utf-8')

        # username_hex = username_bytes.hex()
                
        #         # secret_key_int = random.getrandbits(256)

        #         # secret_key_bytes = secret_key_int.to_bytes(32, byteorder='big')

        # hmac_obj = hmac.new(secret_key_bytes, username_bytes, hashlib.md5)

        #         # Get the HMAC digest
        # digest = hmac_obj.hexdigest()

        # guess = username_hex + ":" + digest
        # print(guess)
        # h = solve(level, guess)
        # if 'hash' in h: hashes[level] = h['hash']

        # start_ns = int(start_time.timestamp() * 1e9)
        # end_ns = int(end_time.timestamp() * 1e9)

        sys_time_MD5_brute_force_precise_ns(start_time,end_time,known_hmac_hex)
        # sys_time_MD5_brute_force(int(start_time) - 6000000,int(end_time) + 100,known_hmac_hex)
        # #md5_brute_force(known_hmac_hex)

        # # Restore /dev/urandom if it was originally present
        # if urandom_exists & random_exists:
        #     os.rename("/dev/urandom_temp", "/dev/urandom")
        #     os.rename("/dev/random_temp", "/dev/random")

        #     print("Done")
        # md5_brute_force(known_hmac_hex)


        # username = "username=user00000"

        # username_bytes = username.encode('utf-8')

        # username_hex = username_bytes.hex()

        # known_hash_value = bytes.fromhex(known_hmac_hex)

        # # Data to be appended
        # appended_data = b'admin=true'

        # # Perform length extension attack
        # new_hmac = md5_length_extension_attack(username_bytes, known_hash_value, appended_data)
        # known_message = 'username=user00000'
        # extension = '&isAdmin=true'

        # # Key length is known to be 256 bits (32 bytes)
        # key_length = 32

        # # Perform the length extension attack
        # new_hmac, new_message = hashpumpy.hashpump(known_hash_value, known_message, extension, key_length)
        # print(f"New HMAC: {new_hmac}, New message: {new_message}")
        # guess = new_message + ":" + new_hmac
        # h = solve(level, guess)
        # print(h)
        # if 'hash' in h: hashes[level] = h['hash']

        # hex_string_generator = iterate_hex_string(len("1cc2a34f703ed2c0a8ea4bdbc0d390d3"))

        # # Getting the first 10 iterations as an example
        # current_highest = 0
        # current_leader = ""
        # for _ in range(256):
        #     this_try = next(hex_string_generator)
        #     guess = "757365726e616d653d61646d696e:" + this_try
        #     # print(f'Crafted Guess: {guess}')
        #     start_time = time.time()
        #     h = solve(level, guess)
        #     end_time = time.time()
        #     total_time = end_time - start_time
        #     if total_time > current_highest:
        #         current_highest = total_time
        #         current_leader = guess
        #     # print(f'Crafted Guess: {guess}, Total time: {total_time}')
        #     # print(h)
        #     if 'hash' in h: hashes[level] = h['hash']
        # print(current_leader)
        # print(current_highest)

        # username = "username=user00000"

        # username_bytes = username.encode('utf-8')

        # username_hex = username_bytes.hex()

        # #known_hash_value = bytes.fromhex(known_hmac_hex)

        # # Data to be appended
        # appended_data = b'&isAdmin=true'

        # # Perform length extension attack
        # new_hmac = md4_length_extension_attack(username_bytes, known_hash_value, appended_data)

        # guess = "757365726e616d653d757365723030303030:" + new_hmac.hex()
        # print(f'Crafted Guess: {guess}')
        
        # h = solve(level, guess)
        # print(h)
        # if 'hash' in h: hashes[level] = h['hash']
        #new_hmac = sha1_length_extension_attack(original_message, known_hmac, appended_data)
        #new_hmac = sha256_length_extension_attack(original_message, known_hmac, appended_data)

        # admin
        # 757365726e616d653d7573657230303030302661646d696e3d74727565
        # isAdmin
        # 757365726e616d653d75736572303030303026697341646d696e3d74727565

        # Display results
        # print(f'Original Message: {original_message.decode()}')
        # print(f'Known Hash Value: {known_hmac_hex}')
        # print(f'Appended Data: {appended_data.decode()}')
        # print(f'Extended Hash: {new_hmac.hex()}')
        # print("\n\nStart below________")

        # print(data['challenge'][152:184])

        #file_path = "collected_hmacs.txt"
        # with open(file_path, 'w') as file:
        #     for i in range(0,1000):
        #         file.write(data['challenge'][152:184])
        #         file.write("\n")
        #         data = fetch(level)


        # Read HMACs from the file
        # with open(file_path, 'r') as file:
        #     hmacs = [line.strip() for line in file]

        # # Set the number of HMACs to visualize in each graph
        # batch_size = 500

        # # Split HMACs into batches
        # hmac_batches = [hmacs[i:i + batch_size] for i in range(0, len(hmacs), batch_size)]

        # # Visualize each batch separately
        # for i, hmac_batch in enumerate(hmac_batches):
        #     plt.hist(hmac_batch, bins='auto')
        #     plt.title(f"HMAC Distribution - Batch {i + 1}")
        #     plt.xlabel("HMAC Values")
        #     plt.ylabel("Frequency")
        #     plt.show()

        # known_hmac_hex = data['challenge'][152:184]
        # known_hmac = bytes.fromhex(known_hmac_hex)

        # # Assuming key is generated using random.getrandbits(256)
        # random.seed(int(start_time))
        # key = random.getrandbits(256)
        # key = b""

        # # Message to be authenticated
        # message = "username=admin"

        # # Generating HMAC using MD5
        # hmac_result = hmac.new(key, message.encode('utf-8'), hashlib.md5).hexdigest()

        # print(f'Generated HMAC: {hmac_result}')
        # #username=admin
        # #757365726e616d653d61646d696e:44a056ea40b0febc548681ff19d1e648
        # #username=user00000
        # #757365726e616d653d757365723030303030:6f228f8c0bc1d2964c6a18613a8bb9fc
        # guess = "757365726e616d653d757365723030303030:" + hmac_result
        # print(f'Crafted Guess: {guess}')
        
        # h = solve(level, guess)
        # print(h)
        # if 'hash' in h: hashes[level] = h['hash']
    elif level == 8:
        print("Placeholder")
        h = solve(level, guess)
        if 'hash' in h: hashes[level] = h['hash']

        # url = "http://crypto.praetorian.com/hash"
        # resp = requests.get(url, headers=token(email))
        # resp.close()
        # print(resp.content)
        
        # if 'hash' in h: hashes[level] = h['hash']
    else:
        pass


# Display all current hash
for k,v in hashes.items():
	print("Level {}: {}".format(k, v))
     
url = "http://crypto.praetorian.com/hash"
resp = requests.get(url, headers=token(email))
resp.close()
print(resp.content)
    