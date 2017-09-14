from util import pkcs7_pad
from oracle import Oracle
from attack import execute_padding_oracle_attack

BLOCK_SIZE = 16
IV = '\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00'
KEY = '\x6b' * 16

def main():
    print "\n---------- Start of Padding Oracle Attack ----------\n"
    plaintext = raw_input("Enter your plaintext WITHOUT padding: ")

    oracle = Oracle(KEY, BLOCK_SIZE)
    padded_plaintext = pkcs7_pad(plaintext, BLOCK_SIZE)
    ciphertext = oracle.aes_padding(padded_plaintext, IV)

    print "\nPlaintext Entered: {}. Number of bytes: {}.".format(plaintext, len(plaintext))
    print "Padded Plaintext: {}. Number of bytes: {}.".format(padded_plaintext, len(padded_plaintext))
    print "Ciphertext: {}. Number of bytes: {}.\n".format(ciphertext, len(ciphertext))

    print "Executing attack..."
    decoded_ciphertext = execute_padding_oracle_attack(oracle, ciphertext, IV)
    print "Attack has commenced.\n"

    print "Decoded Ciphertext: {}. Number of bytes: {}".format(decoded_ciphertext, len(decoded_ciphertext))
    print "\n---------- End of Padding Oracle Attack ----------\n"

if __name__ == '__main__':
    main()