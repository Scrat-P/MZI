from os import urandom

from .utils import bytes2long
from .utils import hexdec
from .utils import long2bytes
from .utils import modinvert


DEFAULT_CURVE = "GOST_3410_2012_Params_1"
CURVE_PARAMS_TEXT = {
    "GOST_3410_2012_Params_1": (
        "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006F",
        "800000000000000000000000000000000000000000000000000000000000000149A1EC142565A545ACFDB77BD9D40CFA8B996712101BEA0EC6346C54374F25BD",
        "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006C",
        "687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF85DC806C4B289F3E965D2DB1416D217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002",
        "1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE6DD9E6C8EC7335DCB228FD1EDF4A39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BD"
    ),
    "GOST_3410_2012_Params_2": (
        "8000000000000000000000000000000000000000000000000000000000000431",
        "8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3",
        "0000000000000000000000000000000000000000000000000000000000000007",
        "5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E",
        "0000000000000000000000000000000000000000000000000000000000000002",
        "08E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8",
    ),
}

CURVE_PARAMS = {}
for c, params in CURVE_PARAMS_TEXT.items():
    CURVE_PARAMS[c] = [hexdec(param) for param in params]


class GOST3410Curve(object):
    def __iter__(self):
        for i in [self.p, self.q, self.a, self.b, self.x, self.y]:
            yield i

    def __init__(self, p, q, a, b, x, y):
        self.p = bytes2long(p)
        self.q = bytes2long(q)
        self.a = bytes2long(a)
        self.b = bytes2long(b)
        self.x = bytes2long(x)
        self.y = bytes2long(y)
        r1 = self.y * self.y % self.p
        r2 = ((self.x * self.x + self.a) * self.x + self.b) % self.p
        if r2 < 0:
            r2 += self.p
        if r1 != r2:
            raise ValueError("Invalid parameters")

    def _pos(self, v):
        if v < 0:
            return v + self.p
        return v

    def _add(self, p1x, p1y, p2x, p2y):
        if p1x == p2x and p1y == p2y:
            t = ((3 * p1x * p1x + self.a) * modinvert(2 * p1y, self.p)) % self.p
        else:
            tx = self._pos(p2x - p1x) % self.p
            ty = self._pos(p2y - p1y) % self.p
            t = (ty * modinvert(tx, self.p)) % self.p
        tx = self._pos(t * t - p1x - p2x) % self.p
        ty = self._pos(t * (p1x - tx) - p1y) % self.p
        return tx, ty

    def exp(self, degree, x=None, y=None):
        x = x or self.x
        y = y or self.y
        tx = x
        ty = y
        degree -= 1
        if degree == 0:
            raise ValueError("Bad degree value")
        while degree != 0:
            if degree & 1 == 1:
                tx, ty = self._add(tx, ty, x, y)
            degree = degree >> 1
            x, y = self._add(x, y, x, y)
        return tx, ty


def public_key(curve, prv):
    return curve.exp(prv)


def sign(curve, prv, digest):
    size = 64
    q = curve.q
    e = bytes2long(digest) % q
    # e = 20798893674476452017134061561508270130637142515379653289952617252661468872421 # test 1 from gost
    if e == 0:
        e = 1
    while True:
        k = bytes2long(urandom(size)) % q
        # k = 53854137677348463731403841147996619241504003434302020712960838528893196233395 # test 1 from gost
        if k == 0:
            continue
        r, _ = curve.exp(k)
        r %= q
        if r == 0:
            continue
        # prv = 55441196065363246126355624130324183196576709222340016572108097750006097525544 # test 1 from gost
        d = prv * r
        k *= e
        s = (d + k) % q
        if s == 0:
            continue
        break

    # return long2bytes(s, size) + long2bytes(r, size)
    return r, s


def verify(curve, pub, digest, signature):
    r, s = signature
    size = 64
    if len(long2bytes(s, size) + long2bytes(r, size)) != size * 2:
        raise ValueError("Invalid signature length")
    q = curve.q
    p = curve.p
    # s = bytes2long(signature[:size])
    # r = bytes2long(signature[size:])
    if r <= 0 or r >= q or s <= 0 or s >= q:
        return False
    e = bytes2long(digest) % curve.q
    # e = 20798893674476452017134061561508270130637142515379653289952617252661468872421 # test 1 from gost
    # pub = ( # test 1 from gost
    #     57520216126176808443631405023338071176630104906313632182896741342206604859403,
    #     17614944419213781543809391949654080031942662045363639260709847859438286763994
    # ) # test 1 from gost
    if e == 0:
        e = 1
    v = modinvert(e, q)
    z1 = s * v % q
    z2 = q - r * v % q
    p1x, p1y = curve.exp(z1)
    q1x, q1y = curve.exp(z2, pub[0], pub[1])

    lm = q1x - p1x
    if lm < 0:
        lm += p
    lm = modinvert(lm, p)
    lm = (lm * (q1y - p1y) % p)**2 % p
    lm = ((lm - p1x - q1x) % p + p) % p

    lm %= q

    return lm == r


def prv_unmarshal(prv):
    return bytes2long(prv[::-1])


def pub_marshal(pub):
    size = 64
    return (long2bytes(pub[1], size) + long2bytes(pub[0], size))[::-1]


def pub_unmarshal(pub):
    size = 64
    pub = pub[::-1]
    return bytes2long(pub[size:]), bytes2long(pub[:size])
