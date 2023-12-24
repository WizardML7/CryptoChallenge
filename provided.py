import requests
try: input = raw_input
except NameError: pass

# Global values
base = "http://crypto.praetorian.com/{}"
email = input("Enter your email address: ")
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


# Fetch level 0
level = 0
hashes = {}
data = fetch(level)

# Level 0 is a freebie and gives you the password
guess = data['challenge']
h = solve(level, guess)

# If we obtained a hash add it to the dict
if 'hash' in h: hashes[level] = h['hash']


# Display all current hash
for k,v in hashes.items():
	print("Level {}: {}".format(k, v))
