MAXCHANGE = 1
MAXLENGTH = 32


def insert_into_pixel(r, g, b, val):
    if len(val) == 1:
        val += "00"
    elif len(val) == 2:
        val += "0"

    x, y, z = tuple(map(int, val))
    
    r = _insert_into_byte(r, x)
    g = _insert_into_byte(g, y)
    b = _insert_into_byte(b, z)

    return (r, g, b)


def alignedbin32(val):
    binary = bin(val)[2:]

    if len(binary) < 32:
       binary = "0" * (32 - len(binary)) + binary
    
    return binary


def get_from_pixel(r, g, b):
    return str(r & 1) + str(g & 1) + str(b & 1)


def get_length(parsed_pixels):
    bin_length = parsed_pixels[:MAXLENGTH]
    return int(bin_length, base=2)


def tobits(s):
    result = ''
    for c in s:
        bits = bin(ord(c))[2:]
        bits = '00000000'[len(bits):] + bits
        result += bits
    return ''.join(result)


def frombits(bits):
    chars = []
    for b in range(len(bits) // 8):
        byte = bits[b * 8:(b + 1)*8]
        chars.append(chr(int(''.join([str(bit) for bit in byte]), 2)))
    return ''.join(chars)


def _insert_into_byte(byte, bit):
    return ((byte >> 1) << 1) | bit
