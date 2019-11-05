class WSIDError(Exception):
    pass

class WSIDValidationError(WSIDError):
    pass

class InsecureIdentityURL(WSIDValidationError):
    pass

class InvalidTimestamps(WSIDValidationError):
    pass

class InvalidSignature(WSIDValidationError):
    pass

