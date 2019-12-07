from md5 import MD5


def XOR(list1, list2):
    return bytearray([a ^ b for a, b in zip(list1, list2)])


def hmac(key, block):
    b = 64

    ipad = bytearray.fromhex('36' * b)
    opad = bytearray.fromhex('5c' * b)

    ikeypad = XOR(key, ipad)
    okeypad = XOR(key, opad)

    hashedikeypad = MD5().md5(ikeypad + block, hex_result=False)

    return MD5().md5(okeypad + hashedikeypad)
    

KEY = bytearray("1234567812345678123456781234567812345678123456781234567812345678", encoding='utf-8')

BLOCKS = [
    bytearray("qwertyuiqwertyuiqwertyuiqwertyuiqwertyuiqwertyuiqwertyuiqwertyui", encoding='utf-8'),  # Basic message
    bytearray("qwertyuiqwertyuiqwertyuiqwertyuiqwertyuiqwertyuiqwertyuiqwertyui", encoding='utf-8'),  # Basic message to check hmac(a) = hmac(a)
    bytearray("0000000000000000000000000000000000000000000000000000000000000000", encoding='utf-8'),  # Just other message
    bytearray("qwertyuiqwertyuiqwertyuiqwertyu7qwertyuiqwertyuiqwertyuiqwertyu7", encoding='utf-8')   # Basic message 'a little' changed
]    


if __name__ == "__main__":
    print()
    for block in BLOCKS:
        print(f"{block} -> {hmac(KEY, block)} -> {len(hmac(KEY, block))}")
