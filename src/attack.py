from util import numerify, stringify, blockify

def execute_padding_oracle_attack(oracle, ciphertext, iv):
    """ Main execution logic for the padding oracle attack.

    Args:
        oracle (:obj): A padding oracle instance.
        ciphertext (str): The ciphertext to be broken.
        iv (str): The initializaton vector.

    Returns:
        broken_ciphertext (str): The broken ciphertext retrieved from the attack.

    """
    ciphertext_numbers = numerify(ciphertext)
    iv_numbers = numerify(iv)
    blocks = blockify(ciphertext_numbers, oracle.block_size)

    broken_ciphertext = []

    # Solves two consecutive blocks each time.
    for block_num, (previous_block, current_block) in enumerate(zip([iv_numbers]+blocks, blocks)):
        broken_block = crack_block(oracle, previous_block, current_block)
        broken_ciphertext += broken_block

        print "Cracked block {}. Value obtained is {}.".format(block_num, broken_block)

    return stringify(broken_ciphertext)

def crack_block(oracle, previous_block, current_block):
    """ Solves two consecutive blocks.

    Args:
        oracle (:obj): A padding oracle instance.
        previous_block (list): The previous block to be modified and used in the attack.
        current_block (list): The block to be broken.

    Returns:
        broken_block (list): The broken block.

    """

    # Recover the last byte of the broken current block.
    last_byte = get_last_byte(oracle, previous_block, current_block)

    # List to store broken bytes.
    decoded_block = [0] * (oracle.block_size - 1) + [last_byte]

    for i in range(oracle.block_size-2, -1, -1):
        # Pad value that is required for the decoded block.
        pad_val = oracle.block_size - i

        # The part of the previous block that is unmodified.
        prefix = previous_block[:i]

        # Modify the bytes of those we have broken to ensure they become the pad_value.
        suffix = [val ^ decoded_block[i+pos+1] ^ pad_val for (pos, val) in enumerate(previous_block[i+1:])]

        '''
        Bruteforce the current byte. Becase we xor the current byte with the guess and the pad _value, the
        pad is only valid when guess == current byte as they cancel out, leaving only the pad_value.
        '''
        for guess in range(256):
            evil_previous_block = prefix + [previous_block[i] ^ guess ^ pad_val] + suffix
            if not oracle.aes_valid_padding(stringify(current_block), stringify(evil_previous_block)):
                continue

            decoded_block[i] = guess
            break
    return decoded_block

def get_last_byte(oracle, previous_block, current_block):
    """ Solves the last byte of two consecutive blocks.

    Args:
        oracle (:obj): A padding oracle instance.
        previous_block (list): The previous block to be modified and used in the attack.
        current_block (list): The block to be broken.

    Returns:
        broken_byte (int): The broken byte.

    Raise:
        ValueError: Unable to obtain the last byte of the current block.

    """

    # The part of the previous block that is unmodified.
    prefix = previous_block[:-1]

    '''
    Bruteforce the last byte. Becase we xor the last byte with the guess and the 1, the
    pad is only valid when guess == current byte as they cancel out, leaving only the pad_value.
    '''
    for guess in range(256):
        evil_previous_block = prefix + [previous_block[-1] ^ guess ^ 1]
        if not oracle.aes_valid_padding(stringify(current_block), stringify(evil_previous_block)):
            continue

        '''
        Note that our guess might not be correct. This is because there can be other cases for having
        a valid pad e.g. \x02\x02 or \x03\x03\x03 etc. We avoid these cases by changing the second last
        byte to something else and see if it decrypts correctly. If it does, we know that the last byte
        is the padded value of \x01.

        '''
        evil_previous_block[-2] = evil_previous_block[-2] ^ 1
        if not oracle.aes_valid_padding(stringify(current_block), stringify(evil_previous_block)):
            continue
        return guess
    raise ValueError('Unable to obtain last byte')
