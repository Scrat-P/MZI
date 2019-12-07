import math
 

class MD5:
    def __init__(self):
        self.rotate_count = [
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
            5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
            4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
        ]
        
        self.T = [int(abs(math.sin(i+1)) * 2**32) & 0xFFFFFFFF for i in range(64)]

        self.A = 0x67452301
        self.B = 0xefcdab89
        self.C = 0x98badcfe
        self.D = 0x10325476
 
        self.functions = [lambda b, c, d: (b & c) | (~b & d)] * 16 + \
            [lambda b, c, d: (d & b) | (~d & c)] * 16 + \
            [lambda b, c, d: b ^ c ^ d] * 16 + \
            [lambda b, c, d: c ^ (b | ~d)] * 16
        
        self.index_functions = [lambda i: i] * 16 + \
            [lambda i: (5*i + 1) % 16] * 16 + \
            [lambda i: (3*i + 5) % 16] * 16 + \
            [lambda i: (7*i) % 16] * 16
 
    @staticmethod
    def to_bytearray(data):
        data_bytes = bytearray(data)
        length = (8 * len(data_bytes)) & 0xffffffffffffffff
        data_bytes.append(0x80)
        while len(data_bytes) % 64 != 56:
            data_bytes.append(0)
        data_bytes += length.to_bytes(8, byteorder='little')   
        return data_bytes


    def left_rotate(self, num, bit_count):
        num &= 0xFFFFFFFF
        return ((num << bit_count) | (num >> (32 - bit_count))) & 0xFFFFFFFF
    

    def parts(self, data, length):
        return [data[i: i + length] for i in range(0, len(data), length)]


    def md5(self, data, hex_result=True):
        for part in self.parts(data, 64):
            a, b, c, d = self.A, self.B, self.C, self.D

            for i in range(64):
                f = self.functions[i](b, c, d)
                index = self.index_functions[i](i)

                x_k = int.from_bytes(part[index * 4: index * 4 + 4], byteorder='little')
                a = (b + self.left_rotate(a + f + self.T[i] + x_k, self.rotate_count[i])) & 0xFFFFFFFF
                a, b, c, d = d, a, b, c

            self.A = self.A + a & 0xFFFFFFFF
            self.B = self.B + b & 0xFFFFFFFF
            self.C = self.C + c & 0xFFFFFFFF
            self.D = self.D + d & 0xFFFFFFFF

        result = sum(x << (32 * i) for i, x in enumerate([self.A, self.B, self.C, self.D]))
        
        
        if hex_result:
            hex_hash = result.to_bytes(16, byteorder='little')
            return '{:032x}'.format(int.from_bytes(hex_hash, byteorder='big'))
        else:
            hex_hash = result.to_bytes(16, byteorder='little')
            return bytearray(hex_hash)


if __name__ == "__main__":
    text = MD5.to_bytearray("mybeautifultextformd5".encode())
    print(MD5().md5(text))  # Matches online
    print(MD5().md5(text))  # Matches online
    print(MD5().md5(text))  # Matches online
    print(MD5().md5(text))  # Matches online
