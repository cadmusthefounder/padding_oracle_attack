from util import encrypt, decrypt, valid_pkcs7_padding

class Oracle:
	"""
	The oracle serves two purposes:
		1) Encryption of plaintext.
		2) Validation of ciphertext having proper padding when decrypted.

	"""

	def __init__(self, key, block_size):
		""" The __init__ method.

		Args:
			key (str): The secret key used for encryption and decryption.
			block_size(int): The block_size used by cipher.

		"""
		self.key = key
		self.block_size = block_size

	def aes_padding(self, plaintext, iv):
		""" Encrypts a plaintext using AES-128 in CBC mode.

		Args:
			plaintext (str): The message to encrypt. Assumes it is padded properly according to PKCS#7 padding format.
			iv (str): The initialiation vector.

		Returns:
			ciphertext (str): The encrypted message.

		"""
		return encrypt(plaintext, iv, self.key)

	def aes_valid_padding(self, ciphertext, iv):
		""" Verifies that the decrypted ciphertext is padded according to PKCS#7.

		Args:
			ciphertext (str): The ciphertext to be decrypted.
			iv (str): The initialiation vector.

		Returns:
			is_valid (bool): True if decrypted ciphertext follows PKCS#7 padding format and False otherwise.
		"""
		padded_plaintext = decrypt(ciphertext, iv, self.key)
		return valid_pkcs7_padding(padded_plaintext, self.block_size)