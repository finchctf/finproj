from dataclasses import dataclass
from typing import NamedTuple

from helper import PUFF,xor,getRand,hashIT

@dataclass
class vStore:
    ID_X: str = None
    S_XV: int = None
    S_X: int = None
    HR_X: str = None
    K_XV: int = None
    C_X: int = None
    C_XV: int = None
    TD_V: bytes = None
    TD_X: bytes = None
    TD_pair: bytes = None


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
    ID_Y: str = None
    S_X: int  = None
    HC_X: str = None
    C_X: int = None
    C_XV: int = None

    def __str__(self) -> str:
        return f"""ID: {self.ID_X}
        S_{self.ID_X}: {self.S_X}
        HC_{self.ID_X}: {self.HC_X}
        C_{self.ID_X}V: {self.C_XV}"""


class Verifier:
    def __init__(self,p: int, id: str):
        self.p = p
        self.puff = PUFF(p)
        self.id = id
        self.client = []
        self.data = vStoreContainer()
    
    def add_client(self,client: str):
        self.client.append(client)

    def generate_challenge(self,client: str):
        assert client in self.client
        #two seeds
        C_X, C_XV = [getRand(self.p) for _ in range(2)]
        data = vStore(ID_X=client)
        self.C_X, self.C_XV = C_X, C_XV
        self.data[client] = data
        return C_X,C_XV
    
    def update_Rvals(self,client: str,R_X,R_XV):
        assert client in self.client
        # data = self.data[client]
        self.R_X, self.R_XV = R_X, R_XV
        # self.data[client] = data
        self.generate_shares(client)

    def generate_shares(self,client: str):
        import hashlib
        assert client in self.client
        data = self.data[client]
        R_AND = getRand(self.p)
        s_XV = (data.C_X + 2 * R_AND) % self.p
        s_X = (data.C_X + R_AND) % self.p
        hr_X = hashIT(self.R_X)
        hc_X = hashIT(self.C_X)
        data.K_XV = self.R_XV
        # data.S_XV, data.S_X, data.HR_X, data.HC_X, data.K_XV = s_XV, s_X, hr_X, hc_X, K_XV

    def get_HC_S_X(self,client: str):
        assert client in self.client
        data = self.data[client]
        return data.HC_X,data.S_X
    
    def update_tempo_keys_and_gen(self,client,TD_X,TD_V,TD_pair,n_X,Sig_X_V,pair_id,verifier_id):
        self._update_tempo_keys(client,TD_X,TD_V,TD_pair,n_X,Sig_X_V)
        return self._gen_tempo_keys(client,pair_id,verifier_id,TD_X,TD_V,TD_pair)

    def _update_tempo_keys(self,client,TD_X,TD_V,TD_pair,n_X,Sig_X_V):
        import time,hashlib
        data = self.data[client]
        nonceX = float(n_X)
        try:
            assert float(time.time()) - nonceX < 60*5
        except AssertionError:
            raise Exception("Nonce Not Fresh")
        Sig_X_V_ = hashlib.sha256(TD_X+TD_V+TD_pair+n_X+data.K_XV.to_bytes((data.K_XV.bit_length()+7)//8,'big')).digest()
        try:
            assert Sig_X_V == Sig_X_V_
        except AssertionError:
            raise Exception("Signature Verification Failed")
        

    def _gen_tempo_keys(self,client: str,pair_id: str,verifier_id: str,TD_X,TD_V,TD_pair):
        import hashlib,time
        nonceVX = str(time.time()).encode()
        data = self.data[client]
        datapair = self.data[pair_id]
        hk_XV = hashlib.sha256(data.K_XV.to_bytes((data.K_XV.bit_length()+7)//8,'big')+nonceVX).digest()
        hk_YV = hashlib.sha256(datapair.K_XV.to_bytes((datapair.K_XV.bit_length()+7)//8,'big')+nonceVX).digest()
        t1 = hashlib.sha256(data.K_XV.to_bytes((data.K_XV.bit_length()+7)//8,'big')+nonceVX).digest()
        t2 = hashlib.sha256(datapair.K_XV.to_bytes((datapair.K_XV.bit_length()+7)//8,'big')+nonceVX).digest()
        R_p = xor(t1,t2)
        D_X = xor(data.S_XV.to_bytes((data.S_XV.bit_length()+7)//8,'big'),hk_XV)
        D_Y = xor(datapair.S_XV.to_bytes((datapair.S_XV.bit_length()+7)//8,'big'),hk_YV)
        SG_V_X = hashlib.sha256(TD_V+TD_X+D_X+R_p+nonceVX+data.K_XV.to_bytes((data.K_XV.bit_length()+7)//8,'big')).digest()
        SG_V_Y = hashlib.sha256(TD_V+TD_pair+D_Y+R_p+nonceVX+datapair.K_XV.to_bytes((datapair.K_XV.bit_length()+7)//8,'big')).digest()
        return (TD_V,TD_X,D_X,R_p,nonceVX,SG_V_X),(TD_V,TD_pair,D_Y,R_p,nonceVX,SG_V_Y)
    



class Device:
    def __init__(self, p:int, C_X:int, C_XV:int ,id:str):
        self.id = id
        self.p = p
        self.puff = PUFF(self.p)
        self.data = dStore(ID_X=self.id,C_X=C_X,C_XV=C_XV)
        self.R_X = self.puff(C_X)
        self.R_XV = self.puff(C_XV)

    def get_RX_V(self,):
        return self.R_X,self.R_XV
    
    def store_vVals(self,HC_X,S_X):
        self.data.HC_X = HC_X
        self.data.S_X = S_X
        
    def gen_tempo_keys(self,pair_id: str,verifier_id: str):
        import hashlib,time
        self.K_XV = self.R_XV
        self.nonceX = str(time.time()).encode()
        self.hk_XV = hashlib.sha256(self.K_XV.to_bytes((self.K_XV.bit_length()+7)//8,'big')+self.nonceX).digest()
        self.TD_X = hashlib.sha256(self.id.encode()+self.hk_XV).digest()
        self.TD_pair = hashlib.sha256(pair_id.encode()+self.hk_XV).digest()
        self.TD_V = hashlib.sha256(verifier_id.encode()+self.hk_XV).digest()
        self.Sig_X_V = hashlib.sha256(self.TD_X+self.TD_V+self.TD_pair+self.nonceX+self.K_XV.to_bytes((self.K_XV.bit_length()+7)//8,'big')).digest()
        return self.TD_X,self.TD_V,self.TD_pair,self.nonceX,self.Sig_X_V

    def verify_and_gen_session_key(self,TD_V,TD_X,D_X,R_p,nonceV,SG_V_X,flag=True):
        self._verify_tempo_keys(TD_V,TD_X,D_X,R_p,nonceV,SG_V_X,flag)
        return self._gen_session_keys(D_X,nonceV,R_p,flag=True)
    
    def _verify_tempo_keys(self,TD_V,TD_X,D_X,R_p,nonceV,SG_V_X,flag=True):
        import hashlib,time
        nonceVX = float(nonceV)
        try:
            assert float(time.time()) - nonceVX < 60*5
        except AssertionError:
            raise Exception("Nonce Not Fresh")
        if flag:
            try:
                assert self.TD_X == TD_X
            except AssertionError:
                raise Exception("TD_X Verification Failed")
        else:
            self.K_XV = self.R_XV
            self.hk_XV = hashlib.sha256(self.K_XV.to_bytes((self.K_XV.bit_length()+7)//8,'big')+nonceV).digest()
        SG_V_X_ = hashlib.sha256(TD_V+TD_X+D_X+R_p+nonceV+self.K_XV.to_bytes((self.K_XV.bit_length()+7)//8,'big')).digest()
        try:
            assert SG_V_X == SG_V_X_
        except AssertionError:
            raise Exception("Signature Verification Failed")
        
    def _gen_session_keys(self,D_X,nonceV,R_p,flag=True):
        import hashlib
        S_XV = int.from_bytes(xor(D_X,self.hk_XV),'big')
        #print(S_XV,self.data.S_X)
        C_X = (S_XV-2*self.data.S_X) % self.p
        H_C_X = hashlib.sha256(C_X.to_bytes((C_X.bit_length()+7)//8,'big')).digest()
        try:
            print(H_C_X,self.data.HC_X,C_X)
            assert H_C_X == self.data.HC_X
        except AssertionError:
            raise Exception("HC_X Verification Failed")
        
        R_X = self.puff(C_X)
        RES_X = hashlib.sha256(hashlib.sha256(R_X.to_bytes((R_X.bit_length()+7)//8,'big')).digest()+nonceV).digest()
        RES_Y = xor(R_p,RES_X)
        K_S = hashlib.sha256(RES_X+RES_Y).digest() if flag else hashlib.sha256(RES_Y+RES_X).digest()
        return K_S

