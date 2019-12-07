class CryptoError(Exception):
    pass


class LocationError(Exception):
    pass


class DecryptionError(CryptoError):
    pass


class VerificationError(CryptoError):
    pass


class SigningError(CryptoError):
    pass