import numpy as np
from argxtract.core import utils
    
def logical_shift_left(value, shift):
    """Logical Shift Left
    
    (LSL) moves each bit of a bitstring left by a specified number of bits.
    Zeros are shifted in at the right end of the bitstring.
    Bits that are shifted off the left end of the bitstring are discarded, 
    except that the last such bit can be produced as a carry output.
    """
    if shift == 0:
        return (value, 0)
    if shift > 31:
        return (None, 0)
    bit_length = utils.get_bit_length(value)
    bits = utils.get_binary_representation(value, bit_length)
    extended_bits = bits
    for i in range(shift):
        extended_bits += '0'
        carry_out = extended_bits[0]
        shifted_value = extended_bits[(-1*bit_length):]
        extended_bits = shifted_value
    new_value = utils.convert_bits_to_type(extended_bits, 'hex')
    carry_out = int(carry_out)
    return (new_value, carry_out)
    
def logical_shift_right(value, shift):
    """Logical Shift Right
    
    (LSR) moves each bit of a bitstring right by a specified number of bits.
    Zeros are shifted in at the left end of the bitstring. 
    Bits that are shifted off the right end of the bitstring are discarded, 
    except that the last such bit can be produced as a carry output.
    """
    if shift == 0:
        return (value, 0)
    if shift > 32:
        return (None, 0)
    bit_length = utils.get_bit_length(value)
    bits = utils.get_binary_representation(value, bit_length)
    extended_bits = bits
    for i in range(shift):
        extended_bits = '0' + extended_bits
        carry_out = extended_bits[-1]
        shifted_value = extended_bits[0:bit_length]
        extended_bits = shifted_value
    new_value = utils.convert_bits_to_type(shifted_value, 'hex')
    carry_out = int(carry_out)
    return (new_value, carry_out)

def arithmetic_shift_right(value, shift):
    """Arithmetic Shift Right
    
    (ASR) moves each bit of a bitstring right by a specified number of bits. 
    Copies of the leftmost bit are shifted in at the left end of the bitstring. 
    Bits that are shifted off the right end of the bitstring are discarded, 
    except that the last such bit can be produced as a carry output.
    """
    if shift == 0:
        return (value, 0)
    if shift > 32:
        return (None, 0)
    bit_length = utils.get_bit_length(value)
    bits = utils.get_binary_representation(value, bit_length)
    leftmost_bit = bits[0]
    extended_bits = bits
    for i in range(shift):
        extended_bits = leftmost_bit + extended_bits
        carry_out = extended_bits[-1]
        shifted_value = extended_bits[0:bit_length]
        extended_bits = shifted_value
    new_value = utils.convert_bits_to_type(shifted_value, 'hex')
    carry_out = int(carry_out)
    return (new_value, carry_out)
    
def rotate_right(value, shift):
    """Rotate Right
    
    (ROR) moves each bit of a bitstring right by a specified number of bits. 
    Each bit that is shifted off the right end of the bitstring is 
    re-introduced at the left end. The last bit shifted off the the right end 
    of the bitstring can be produced as a carry output.
    """
    if shift == 0:
        return (value, 0)
    if shift > 31:
        return (None, 0)
    bit_length = utils.get_bit_length(value)
    bits = utils.get_binary_representation(value, bit_length)
    shifted_bits = bits
    for i in range(shift):
        rightmost_bit = bits[-1]
        shifted_bits = rightmost_bit + bits
        bits = shifted_bits[0:bit_length]
    new_value = utils.convert_bits_to_type(bits, 'hex')
    carry_out = int(rightmost_bit)
    return (new_value, carry_out)
    
def rotate_right_with_extend(value, carry_in=None):
    """Rotate Right with Extend
    
    (RRX) moves each bit of a bitstring right by one bit. 
    The carry input is shifted in at the left end of the bitstring. 
    The bit shifted off the right end of the bitstring can be produced 
    as a carry output.
    """
    if carry_in == None: carry_in = '0'
    if type(carry_in) is int: carry_in = str(carry_in)
    bit_length = utils.get_bit_length(value)
    bits = utils.get_binary_representation(value, bit_length)
    shifted_bits = bits
    carry_out = int(bits[-1])
    shifted_bits = carry_in + bits
    bits = shifted_bits[0:bit_length]
    new_value = utils.convert_bits_to_type(bits, 'hex')
    return (new_value, carry_out)
    
def add_with_carry(x, y, carry_in=0, num_bits = 32, sub=False):
    orig_x = x
    orig_y = y
    if sub == True:
        np_dtype = utils.get_numpy_type([x, y])
        y = np.bitwise_not(
            y.astype(np_dtype),
            dtype=np_dtype,
            casting='safe'
        )
    try:
        if num_bits == 32:
            np.seterr(over='ignore')
            uint_x = np.uint32(x)
            np.seterr(over='ignore')
            int_x = np.int32(x)
            np.seterr(over='ignore')
            uint_y = np.uint32(y)
            np.seterr(over='ignore')
            int_y = np.int32(y)
            np.seterr(over='ignore')
            uint_carry_in = np.uint32(carry_in)
        elif num_bits == 16:
            np.seterr(over='ignore')
            uint_x = np.uint16(x)
            np.seterr(over='ignore')
            int_x = np.int16(x)
            np.seterr(over='ignore')
            uint_y = np.uint16(y)
            np.seterr(over='ignore')
            int_y = np.int16(y)
            np.seterr(over='ignore')
            uint_carry_in = np.uint16(carry_in)
        elif num_bits == 8:
            np.seterr(over='ignore')
            uint_x = np.uint8(x)
            np.seterr(over='ignore')
            int_x = np.int8(x)
            np.seterr(over='ignore')
            uint_y = np.uint8(y)
            np.seterr(over='ignore')
            int_y = np.int8(y)
            np.seterr(over='ignore')
            uint_carry_in = np.uint8(carry_in)
            
        np.seterr(over='ignore')
        unsigned_sum = uint_x + uint_y + uint_carry_in
        np.seterr(over='ignore')
        signed_sum = int_x + int_y + uint_carry_in
        
        # Set result.
        np.seterr(over='ignore')
        result = np.uint32(unsigned_sum)
        
        # Set carry.
        np.seterr(over='ignore')
        if np.uint32(result) == unsigned_sum:
            carry_out = 0
        else:
            carry_out = 1

        # Set overflow.
        np.seterr(over='ignore')
        if np.int32(result) == signed_sum:
            overflow = 0
        else:
            overflow = 1
            
        if sub == True:
            existing = result
            if carry_in == 1:
                if orig_x >= orig_y:
                    carry_out = 1
            if carry_in == 0:
                if orig_x > orig_y:
                    carry_out = 1
        return (result, carry_out, overflow)
    except:
        return (None, None, None)
    
def is_zero_bit(x):
    for bit in x:
        if bit != '0':
            return 0
    return 1
    
def sign_extend(value, total_bits=32):
    bin_value = bin(int('1'+value, 16))[3:]
    top_bit = bin_value[0]
    length_bits = len(bin_value)
    num_sign_bits = total_bits - length_bits
    extended_bits = ''
    for i in range(num_sign_bits):
        extended_bits += top_bit
    extended_bits += bin_value
    extended_hex = '%0*x' % ((len(extended_bits) + 3) // 4, int(extended_bits, 2))
    return extended_hex