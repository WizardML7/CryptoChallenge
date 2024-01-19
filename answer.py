import requests
import zlib
import base64
import wave
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime
import time
import random
import hmac
import hashlib

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

def md5_length_extension_attack(original_message, known_hash_value, appended_data):
    # Known length of the original message
    original_length = len(original_message)

    # Construct the padding for the original message
    padding = b'\x80' + b'\x00' * ((64 - (original_length + 9) % 64) % 64)

    # Append the length of the original message (in bits) to the padding
    padded_message = original_message + padding + (original_length * 8).to_bytes(8, 'little')

    # Calculate the HMAC using the known hash value as the key
    hmac_obj = hmac.new(known_hash_value, msg=padded_message, digestmod=hashlib.md5)

    # Continue hashing with the appended data
    hmac_obj.update(appended_data)

    # Obtain the final hash value
    new_hash_value = hmac_obj.digest()

    return new_hash_value

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

def md5_brute_force():
    count = 0
    max_iterations = 1000  # Set a maximum number of iterations

    username = "username=admin"

    username_bytes = username.encode('utf-8')

    username_hex = username_bytes.hex()

    while count < max_iterations:
        random.seed(count)

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




hashes = {}

for i in range(7, 8):
    level = i
    data = fetch(level)
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

        md5_brute_force()
        # Known original message
        original_message = b'username=user00000'

        # Known hash value (input manually)
        # known_hash_value_hex = input("Enter the known hash value (hex): ")
        # known_hash_value = bytes.fromhex(known_hash_value_hex)

        # Known HMAC (input manually)
        known_hmac_hex = input("Enter the known HMAC value (hex): ")
        known_hmac = bytes.fromhex(known_hmac_hex)

        # Data to be appended
        appended_data = b'username=admin'

        # Perform length extension attack
        new_hmac = md5_length_extension_attack(original_message, known_hmac, appended_data)
        #new_hmac = sha1_length_extension_attack(original_message, known_hmac, appended_data)
        #new_hmac = sha256_length_extension_attack(original_message, known_hmac, appended_data)


        # Display results
        print(f'Original Message: {original_message.decode()}')
        print(f'Known Hash Value: {known_hmac_hex}')
        print(f'Appended Data: {appended_data.decode()}')
        print(f'Extended Hash: {new_hmac.hex()}')

        guess = "757365726e616d653d757365723030303030757365726e616d653d61646d696e:" + new_hmac.hex()
        print(f'Crafted Guess: {guess}')
        
        h = solve(level, guess)
        print(h)
        if 'hash' in h: hashes[level] = h['hash']
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
    