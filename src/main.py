from util import *
from oracle import Oracle

def execute_padding_oracle_attack(oracle, ciphertext, iv):
    ciphertext_numbers = numerify(ciphertext)
    iv_numbers = numerify(iv)
    blocks = blockify(ciphertext_numbers)

    decoded_ciphertext = []

    for block_num, (previous_block, current_block) in enumerate(zip([iv_numbers]+blocks, blocks)):
        block_ans = crack_blocks(oracle, previous_block, current_block)
        decoded_ciphertext += block_ans

    return stringify(decoded_ciphertext)

def crack_blocks(oracle, previous_block, current_block, block_size=16):
    last_byte = get_last_byte(oracle, previous_block, current_block)

    decoded_ciphertext = [0] * (block_size - 1) + [last_byte]

    for i in range(block_size-2, -1, -1):
        pad_val = block_size - i
        prefix = previous_block[:i]
        suffix = [val ^ decoded_ciphertext[i+pos+1] ^ pad_val for (pos, val) in enumerate(previous_block[i+1:])]
        for guess in range(256):
            evil_previous_block = prefix + [previous_block[i] ^ guess ^ pad_val] + suffix
            if not oracle.aes_valid_padding(stringify(current_block), stringify(evil_previous_block)):
                continue
            decoded_ciphertext[i] = guess
            break
    return decoded_ciphertext

def get_last_byte(oracle, previous_block, current_block, block_size=16):
    prefix = previous_block[:-1]
    for guess in range(256):
        evil_previous_block = prefix + [previous_block[-1] ^ guess ^ 1]
        if not oracle.aes_valid_padding(stringify(current_block), stringify(evil_previous_block)):
            continue

        # Guess might be correct but need to check edge case.
        evil_previous_block[-2] = evil_previous_block[-2] ^ 1
        if not oracle.aes_valid_padding(stringify(current_block), stringify(evil_previous_block)):
            continue
        return guess
    raise ValueError('Unable to obtain last byte')

def main():
    plaintext = raw_input("Enter your plaintext: ")
    iv = '\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00'
    key = '\x6b' * 16
    padded_plaintext = pkcs7_pad(plaintext)

    oracle = Oracle(key)
    ciphertext = oracle.aes_padding(padded_plaintext, iv)

    decoded_ciphertext = execute_padding_oracle_attack(oracle, ciphertext, iv)
    print "Decoded Ciphertext: {}".format(decoded_ciphertext)

if __name__ == '__main__':
    main()