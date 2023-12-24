import requests

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
    for i in range(1,25):
        decrypted_text = ""
        for char in ciphertext:
            if char.isalpha():
                # Determine whether the character is uppercase or lowercase
                is_upper = char.isupper()
                
                # Apply the Caesar cipher decryption
                decrypted_char = chr((ord(char) - i - ord('A' if is_upper else 'a')) % 26 + ord('A' if is_upper else 'a'))

                decrypted_text += decrypted_char
            else:
                decrypted_text += char

        print(decrypted_text)

hashes = {}

for i in range(0, 2):
    level = i
    data = fetch(level)

    if level == 0:
        guess = data['challenge']
        h = solve(level, guess)
        if 'hash' in h: hashes[level] = h['hash']
    elif level == 1:
        caesarCipher(data['challenge'])
        guess = input("Put in the cleartext for level one here: ")
        h = solve(level, guess)
        if 'hash' in h: hashes[level] = h['hash']
    elif level == 2:
        print("Level 2")
    else:
        pass


# Display all current hash
for k,v in hashes.items():
	print("Level {}: {}".format(k, v))