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
