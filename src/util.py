from Crypto.Cipher import AES

def encrypt(plaintext, iv, key):
	cipher = AES.new(key, AES.MODE_CBC, iv)
	return cipher.encrypt(plaintext)

def decrypt(ciphertext, iv, key):
	cipher = AES.new(key, AES.MODE_CBC, iv)
	return cipher.decrypt(ciphertext)

def pkcs7_pad(text, block_size=16):
	length = block_size - (len(text) % block_size)
	text += chr(length) * length
	return text

def pkcs7_unpad(text, block_size=16):
	if not valid_pkcs7_padding(text):
		raise ValueError('Invalid PKCS7 padding.')
	return text[:-ord(text[-1])]

def valid_pkcs7_padding(text, block_size=16):
	if not text.strip(): return False

	last_value = ord(text[-1])
	if last_value < 1 or last_value > block_size: return False

	return all([e == chr(last_value) for e in text[-last_value:]])

def numerify(string):
	return list(map(lambda c: ord(c), string))

def stringify(numbers):
	return "".join(map(lambda i: chr(i), numbers))

def blockify(numbers, block_size=16):
	return [numbers[i:i+block_size] for i in range(0, len(numbers), block_size)]
