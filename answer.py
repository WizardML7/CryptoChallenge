import requests
import zlib
import base64
import wave
import numpy as np
import matplotlib.pyplot as plt

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

hashes = {}

for i in range(6, 7):
    level = i
    data = fetch(level)

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
        print("Placeholder")
    elif level == 7:
        print("Placeholder")
    elif level == 8:
        print("Placeholder")

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
    