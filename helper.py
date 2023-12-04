from dataclasses import dataclass

@dataclass
class vStore:
    ID_X: str = None
    S_XV: int = None
    HR_X: str = None
    K_XV: int = None

    def __str__(self) -> str:
        return f"""ID: {self.ID_X}
        S_{self.ID_X}V: {self.S_XV}
        HR_{self.ID_X}: {self.HR_X}
        K_{self.ID_X}V: {self.K_XV}"""

class vStoreContainer:
    def __init__(self):
        self.data = {}

    def __getitem__(self,client):
        return self.data[client]

    def __setitem__(self,client,vStore):
        self.data[client] = vStore

@dataclass
class dStore:
    ID_X: str = None
    S_X: int  = None
    HC_X: str = None
    C_XV: int = None

    def __str__(self) -> str:
        return f"""ID: {self.ID_X}
        S_{self.ID_X}: {self.S_X}
        HC_{self.ID_X}: {self.HC_X}
        C_{self.ID_X}V: {self.C_XV}"""


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


def hashIT(*args) -> bytes:
    from hashlib import sha1
    x=b"".join([i if type(i)==bytes else i.to_bytes((i.bit_length()+7)//8,"big") for i in args])
    return sha1(x).digest()
    



def xor(a,b):
    return b''.join([bytes([i^j]) for i,j in zip(a,b)])

def calcNonce():
    from time import time
    return str(time()).encode()