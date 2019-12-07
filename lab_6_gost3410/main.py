import json
from os import urandom
from binascii import hexlify
from os.path import exists, basename

from exceptions import (
    CryptoError,
    LocationError,
    DecryptionError,
    VerificationError,
    SigningError,
)
from gost_algorithm import gost341012
from gost_algorithm.gost341112 import GOST341112


def gost3411_2012(data):
    dgst = GOST341112(digest_size=256)
    dgst.update(data)

    return dgst.digest()


def create_signature(curve, prv, dgst, filename='', filesize=0):
    signature = gost341012.sign(curve, prv, dgst)
    pub = gost341012.public_key(curve, prv)
    s = {
        'algo': 'gost_3410_2012',
        
        'open_key_x': pub[0],
        'open_key_y': pub[1],

        'curve_p': curve.p,
        'curve_a': curve.a,
        'curve_b': curve.b,
        'curve_x': curve.x,
        'curve_y': curve.y,
        'curve_q': curve.q,

        'sign_r': signature[0],
        'sign_s': signature[1],

        'filename': filename,
        'filesize': filesize
    }

    return json.dumps(s, indent=4)


def verify_signature(dgst, s, own_pubkey=None):
    try:
        if s['algo'] != 'gost_3410_2012':
            raise DecryptionError('Wrong signature identifier')

        pub = int(s['open_key_x']), int(s['open_key_y'])

        if own_pubkey and pub != own_pubkey:
            raise VerificationError('Open keys does not match!')

        p = int(s['curve_p'])
        q = int(s['curve_q'])
        a = int(s['curve_a'])
        b = int(s['curve_b'])
        x = int(s['curve_x'])
        y = int(s['curve_y'])

        curve = gost341012.GOST3410Curve(p, q, a, b, x, y)

        signature = int(s['sign_r']), int(s['sign_s'])

    except Exception as e:
        raise VerificationError(e)
    else:
        return gost341012.verify(curve, pub, dgst, signature)


def sign_file(path, curve, prv):
    try:
        with open(path, 'rb') as file:
            data = file.read()
            dgst = gost3411_2012(data)
            print('Message hash:', str(hexlify(dgst)), end='\n\n')

            signature = create_signature(curve, prv, dgst, filename=basename(path), filesize=len(data))
            print('Generated signature:')
            print(signature, end='\n\n')

            with open(path[:-4] + '_sign.txt', 'w') as sign_f:
                sign_f.write(signature)
    except Exception as e:
        raise SigningError(e)
    else:
        return True


def verify_file(filepath, sign_path=None, own_pubkey=None):
    if not sign_path:
        sign_path = filepath[:-4] + '_sign.txt'
        if not exists(sign_path):
            raise LocationError('\nCant find {0}.sign in folder, please point path to .sign file'.format(basename(filepath)))

    try:
        with open(filepath, 'rb') as file, open(sign_path, 'r') as sign_f:
            data = file.read()
            signature = json.loads(sign_f.read())
            
            dgst = gost3411_2012(data)
            is_verified = verify_signature(dgst, signature, own_pubkey)

            if not is_verified:
                raise VerificationError('File not verified')
    except Exception as e:
        raise VerificationError(e)


if __name__ == '__main__':
    curve_params = gost341012.CURVE_PARAMS["GOST_3410_2012_Params_1"]
    curve = gost341012.GOST3410Curve(*curve_params)

    prv_raw = urandom(32)
    prv = gost341012.prv_unmarshal(prv_raw)
    sign_file('./test_files/lorem.txt', curve, prv)
    
    try:
        verify_file('./test_files/lorem.txt')
    except Exception as e:
        print("VERIFIED WITH EXCEPTION!", str(e), sep='\n')
    else:
        print("SUCCESSFULLY VERIFIED!")
