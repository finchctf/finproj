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

    def __delitem__(self,client):
        del self.data[client]

    def __contains__(self,client):
        return client in self.data
    
    def __str__(self) -> str:
        return str(self.data)
    
    def __len__(self) -> int:
        return len(self.data)
    
    def __iter__(self):
        return iter(self.data)
    

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
    from itertools import cycle
    if type(a)==int:
        a = a.to_bytes((a.bit_length()+7)//8,"big")
    if type(b)==int:
        b = b.to_bytes((b.bit_length()+7)//8,"big")
    if len(a) < len(b):
        a,b = b,a
    return b''.join([bytes([i^j]) for i,j in zip(a,cycle(b))])

def calcNonce():
    from time import time
    return str(time()).encode()