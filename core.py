from dataclasses import dataclass

@dataclass
class vStore:
    ID_X: str
    S_XV: int
    HR_X: str
    K_XV: int

@dataclass
class dStore:
    ID_X: str
    S_X: int
    HC_X: str
    C_XV: int

class PUFF:
    def __init__(self,P):
        self.P = P
        self.genRand()

    def __call__(self,challenge):
        return (challenge + self.PUF_R) % self.P

    def genRand(self):
        import random
        self.PUF_R = random.randint(1, self.P - 1)
        return self.PUF_R

class Verifier:
    def __init__(self,p: int,client: str):
        self.p = p
        self.client = client
        
    def generate_challenge(self,):
        import random
        self.C_X = random.randint(1, self.p - 1)
        self.C_XV = random.randint(1, self.p - 1)
        self.Rand_X = random.randint(1, self.p - 1)
        return self.C_X,self.C_XV
    
    def update_Rvals(self,R_X,R_XV):
        self.R_X = R_X
        self.R_XV = R_XV
        self.generate_shares()

    def generate_shares(self,):
        import hashlib
        self.s_XV = (self.C_X + 2 * self.Rand_X) % self.p
        self.s_X = (self.C_X + self.Rand_X) % self.p
        self.hr_X = hashlib.sha256(self.R_X.to_bytes(self.R_X.bit_length()//8+1,'big')).hexdigest()
        self.hc_X = hashlib.sha256(self.C_X.to_bytes(self.C_X.bit_length()//8+1,'big')).hexdigest()
        self.K_XV = self.R_XV
        self.store()

    def get_HC_S_X(self,):
        return self.hc_X,self.s_X

    def store(self,):
        self.data = vStore(self.client,self.s_XV,self.hr_X,self.K_XV)
    
class Device:
    def __init__(self, p:int, C_X:int, C_XV:int ,name:str):
        self.name = name
        self.p = p
        self.C_X = C_X
        self.C_XV = C_XV
        self.puff = PUFF(self.p)
        self.generate_p1()

    def generate_p1(self,):
        self.R_X = self.puff(self.C_X)
        self.R_XV = self.puff(self.C_XV)

    def get_RX_V(self,):
        return self.R_X,self.R_XV

    def update_vals(self,HC_X,S_X):
        self.HC_X = HC_X
        self.S_X = S_X
        self.store()

    def store(self,):
        self.data = dStore(self.name,self.S_X,self.HC_X,self.C_XV)

    def gen_tempo_keys(self,):
        import hashlib
        from os import urandom
        self.K_XV = self.R_XV
        self.N_X = urandom(16)
        self.hk_XV = hash.sha256(self.K_XV.to_bytes(self.K_XV.bit_length()//8+1,'big')+self.N_X).hexdigest()
        self.TD_X = hash.sha256(self.i

if __name__ == "__main__":
    # common parameter
    p=2**200
    client = "DeviceA"
    #verifier
    vA = Verifier(p,client)
    C_A,C_AV = vA.generate_challenge()
    #print(C_A,C_AV)
    #deviceA
    d = Device(p,C_A,C_AV,"DeviceA")
    R_A, R_AV = d.R_X, d.R_XV
    #print(R_A,R_AV)
    #verifier
    vA.update_Rvals(R_A,R_AV)
    #print(vA.data)
    HC_A = vA.hc_X
    S_A = vA.s_X

    #deviceA
    d.update_vals(HC_A,S_A)

    print(d.data)

    #verifier
    print(vA.data)




