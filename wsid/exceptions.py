class WSIDError(Exception):
    pass

class InsecureIdentityURL(WSIDError):
    pass

class InvalidTimestamps(WSIDError):
    pass

class InvalidSignature(WSIDError):
    pass
