from util import *
from oracle import Oracle

def get_nice_string(list_or_iterator):
    return "[" + ", ".join( str(x) for x in list_or_iterator) + "]"

def test_util():
    plaintext = 'Hello World'
    iv = '\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00'
    key = '\x6b' * 16

    padded_plaintext = pkcs7_pad(plaintext)
    ciphertext = encrypt(padded_plaintext, iv, key)
    decrypted_ciphertext = decrypt(ciphertext, iv, key)
    unpad_decrypted_ciphertext = pkcs7_unpad(decrypted_ciphertext)

    print repr("Plaintext: " + plaintext)
    print repr("Iv: " + iv)
    print repr("Key: " + key)
    print repr("Padded Plaintext: " + padded_plaintext)
    print repr("Ciphertext: " + ciphertext)
    print repr("Decrypted Ciphertext: " + decrypted_ciphertext)
    print repr("Unpad Decrypted Ciphertext: " + unpad_decrypted_ciphertext)

    invalid_pad_text = ['', 'Hello World\x00', 'Hello World\x11', 'Hello World\x05\x05\x05\x05\x04']
    print "Invalid Pad: %s" % all([not valid_pkcs7_padding(e) for e in invalid_pad_text])
    print "Valid Pad: %s" % valid_pkcs7_padding(padded_plaintext)

    padded_plaintext_int = numerify(padded_plaintext)
    new_padded_plaintext = stringify(padded_plaintext_int)
    blocks = blockify(padded_plaintext_int)

    print repr("Padded Plaintext Int: " + get_nice_string(padded_plaintext_int))
    print repr("New Padded Plaintext: " + new_padded_plaintext)
    print repr("Blocks: " + get_nice_string(blocks))

def execute_padding_oracle_attack(oracle, ciphertext, iv):
    ciphertext_numbers = numerify(ciphertext)
    iv_numbers = numerify(iv)
    blocks = blockify(ciphertext_numbers)

    decoded_ciphertext = []

    for block_num, (previous_block, current_block) in enumerate(zip([iv_numbers]+blocks, blocks)):
        decoded_ciphertext += crack_blocks(oracle, previous_block, current_block)
    return stringify(decoded_ciphertext)

def crack_blocks(oracle, previous_block, current_block, block_size=16):
    last_byte = get_last_byte(oracle, previous_block, current_block)
    print "Last Byte: {}".format(last_byte)
    return []

def get_last_byte(oracle, previous_block, current_block, block_size=16):
    prefix = previous_block[:-1]
    for guess in range(256):
        evil_previous_block = prefix + [previous_block[-1] ^ guess ^ 1]
        if not oracle.aes_valid_padding(stringify(current_block), stringify(evil_previous_block)):
            continue

        # Guess might be correct but need to check edge case.
        evil_previous_block[-2] = evil_previous_block[-2] ^ 1
        print "Evil previous block: {}".format(evil_previous_block)
        if not oracle.aes_valid_padding(stringify(current_block), stringify(evil_previous_block)):
            continue
        return guess
    raise ValueError('Unable to obtain last byte')

def main():
    # test_util()
    plaintext = 'Hello World'
    iv = '\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00'
    key = '\x6b' * 16
    padded_plaintext = pkcs7_pad(plaintext)

    oracle = Oracle(key)
    ciphertext = oracle.aes_padding(padded_plaintext, iv)

    decoded_ciphertext = execute_padding_oracle_attack(oracle, ciphertext, iv)
    print "Decoded Ciphertext: {}".format(decoded_ciphertext)

if __name__ == '__main__':
    main()