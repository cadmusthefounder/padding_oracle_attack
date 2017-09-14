from Crypto.Cipher import AES

def encrypt(plaintext, iv, key):
	""" Encrypts a plaintext using AES-128 in CBC mode.

	Args:
		plaintext (str): The message to encrypt.
		iv (str): The initialiation vector.
		key (str): The secret key to be used.

	Returns:
		ciphertext (str): The encrypted message.

	"""
	cipher = AES.new(key, AES.MODE_CBC, iv)
	return cipher.encrypt(plaintext)

def decrypt(ciphertext, iv, key):
	""" Decrypts a ciphertext using AES-128 in CBC mode.

	Args:
		ciphertext (str): The encrypted message.
		iv (str): The initialiation vector.
		key (str): The secret key to be used.

	Returns:
		plaintext (str): The decrypted message.

	"""
	cipher = AES.new(key, AES.MODE_CBC, iv)
	return cipher.decrypt(ciphertext)

def pkcs7_pad(msg, block_size):
	""" Pads a message according to PKCS#7.

	Args:
		msg (str): The message to be padded.
		block_size (int): The block size.

	Returns:
		padded_msg (str): The padded message.

	"""
	length = block_size - (len(msg) % block_size)
	msg += chr(length) * length
	return msg

def pkcs7_unpad(msg, block_size):
	""" Unpads a message according to PKCS#7.

	Args:
		padded_msg (str): The message to be unpadded.
		block_size (int): The block size.

	Returns:
		msg (str): The unpadded message.

	Raises:
		ValueError: Thrown when the message does not follow the PKCS#7 padding format.

	"""
	if not valid_pkcs7_padding(msg):
		raise ValueError('Invalid PKCS7 padding.')
	return msg[:-ord(msg[-1])]

def valid_pkcs7_padding(msg, block_size):
	""" Verifies that a message is padded according to PKCS#7.

	Args:
		msg (str): The message to be verified.
		block_size (int): The block size.

	Returns:
		is_valid (bool): True if message follows PKCS#7 padding format and False otherwise.

	"""
	if not msg.strip(): return False

	last_value = ord(msg[-1])
	if last_value < 1 or last_value > block_size: return False

	return all([e == chr(last_value) for e in msg[-last_value:]])

def numerify(string):
	""" Converts a string into a list of integers that represents the Unicode point of each character.

	Args:
		string (str): The string to be converted.

	Returns:
		integer_list (list): A list of integers that represents the Unicode point of each character.

	"""
	return list(map(lambda c: ord(c), string))

def stringify(numbers):
	""" Converts a list of integers that represents the Unicode point of each character to a string.

	Args:
		numbers (list): A list of integers that represents the Unicode point of each character.

	Returns:
		string (str): The converted string.

	"""
	return "".join(map(lambda i: chr(i), numbers))

def blockify(numbers, block_size):
	""" Converts a list of integers to a 2D matrix, where each row has block_size-th elements.

	Args:
		numbers (list): A list of integers that represents the Unicode point of each character.
		block_size (int): The block size.

	Returns:
		2D_matrix (list of list): The 2D matrix.

	"""
	return [numbers[i:i+block_size] for i in range(0, len(numbers), block_size)]
