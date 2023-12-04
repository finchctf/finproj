def getRand(P):
    from os import urandom
    return int.from_bytes(urandom(P.bit_length()//8-1),'big')

class PUFF:
    def __init__(self,P):
        self.P = P

    def __call__(self,challenge):
        import random
        random.seed(challenge)
        return random.randint(2,self.P-1)

def hashIT(x: bytes) -> str:
    from hashlib import sha1
    return sha1(x).hexdigest()

def hashIT(x: int) -> str:
    from hashlib import sha1
    return sha1(x.to_bytes(x.bit_length()//8+1,'big')).hexdigest()