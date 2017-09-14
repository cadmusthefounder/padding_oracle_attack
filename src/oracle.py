from util import encrypt, decrypt, valid_pkcs7_padding

class Oracle:

	def __init__(self, key):
		self.key = key

	def aes_padding(self, plaintext, iv):
		return encrypt(plaintext, iv, self.key)

	def aes_valid_padding(self, ciphertext, iv):
		padded_plaintext = decrypt(ciphertext, iv, self.key)
		return valid_pkcs7_padding(padded_plaintext)