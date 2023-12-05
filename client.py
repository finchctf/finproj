from helper import *
class Device_enroll:
    def __init__(self, p:int ,id:str):
        self.id = id
        self.p = p
        self.puff = PUFF(self.p)
        self.data = dStore(ID_X=self.id)

    def get_CX_CXV(self,C_X,C_XV):
        self.C_X, self.C_XV = C_X, C_XV

    def get_RX_RXV(self,):
        RX = self.puff(self.C_X)
        #print("*"*20,RX)
        RXV = self.puff(self.C_XV)
        return RX,RXV
        
    def store_vVals(self,id_X,S_X,HC_X,C_XV):
        data = self.data
        data.S_X = S_X
        data.HC_X = HC_X
        data.C_XV = C_XV
        self.data = data

class Device_DD_AKE:
    def __init__(self,p,id,data):
        self.p = p
        self.id = id.encode()
        self.data = data
        self.puff = PUFF(self.p)

    def gen_tempo_keys(self,pair_id: str,verifier_id: str):
        K_XV = self.puff(self.data.C_XV)
        nonceX = calcNonce()
        hk_XV = hashIT(K_XV,nonceX)
        TD_X = hashIT(self.id,hk_XV)
        TD_pair = hashIT(pair_id.encode(),hk_XV)
        TD_V = hashIT(verifier_id.encode(),hk_XV)
        Sig_X_V = hashIT(TD_X+TD_V+TD_pair+nonceX,K_XV)
        return TD_X,TD_V,TD_pair,nonceX,Sig_X_V
    
    def verify_and_gen_session_key(self,TD_V,TD_X,D_X,R_p,nonceV,SG_V_X,flag=True):
        self._verify_tempo_keys(TD_V,TD_X,D_X,R_p,nonceV,SG_V_X,flag)
        return self._gen_session_keys(D_X,nonceV,R_p,flag)
    
    def _verify_tempo_keys(self,TD_V,TD_X,D_X,R_p,nonceV,SG_V_X,flag=True):
        nonceVX = float(nonceV)
        try:
            assert float(calcNonce()) - nonceVX < 60*5
        except AssertionError:
            raise Exception("Nonce Not Fresh")
        K_XV = self.puff(self.data.C_XV)
        SG_V_X_ = hashIT(TD_V,TD_X,D_X,R_p,nonceV,K_XV)
        try:
            assert SG_V_X == SG_V_X_
        except AssertionError:
            raise Exception("Signature Verification Failed")
        
    def _gen_session_keys(self,D_X,nonceV,R_p,flag=True):
        hk_XV = hashIT(self.puff(self.data.C_XV),nonceV)
        S_XV = D_X ^ int.from_bytes(hk_XV,'big')
        #(2*S_A-S_AV)%p
        C_X = (2*self.data.S_X-S_XV) % self.p
        H_C_X = hashIT(C_X)
        try:
            assert H_C_X == self.data.HC_X
        except AssertionError:
            raise Exception("HC_X Verification Failed")
        
        R_X = self.puff(C_X)
        #print(R_X)
        RES_X = hashIT(hashIT(R_X),nonceV)
        #print("+"*35,RES_X)
        RES_Y = xor(R_p,RES_X)
       # print("*"*35,RES_Y)
        K_S = hashIT(RES_X,RES_Y) if flag else hashIT(RES_Y,RES_X)
        return K_S

class Device_DV_AKE():
    def __init__(self,p,id,data):
        self.p = p
        self.id = id.encode()
        self.data = data
        self.puff = PUFF(self.p)

    def gen_tempo_keys(self,verifier_id: str):
        K_XV = self.puff(self.data.C_XV)
        nonceX = calcNonce()
        hk_XV = hashIT(K_XV,nonceX)
        TD_X = hashIT(self.id,hk_XV)
        TD_V = hashIT(verifier_id.encode(),hk_XV)
        Sig_X_V = hashIT(TD_X+TD_V+nonceX,K_XV)
        return TD_X,TD_V,nonceX,Sig_X_V
    
    def verify_and_gen_session_key(self,TD_V,TD_X,P_XV, P_X , Cl , N_V , SG_V_X):
        self._verify_tempo_keys(TD_V,TD_X,P_XV, P_X , Cl , N_V , SG_V_X)
        return self._gen_session_keys(P_XV, P_X , Cl , N_V)

    def _verify_tempo_keys(self,TD_V,TD_X,P_XV, P_X , Cl , N_V , SG_V_X):
        nonceVX = float(N_V)
        try:
            assert float(calcNonce()) - nonceVX < 60*5
        except AssertionError:
            raise Exception("Nonce Not Fresh")
        K_XV = self.puff(self.data.C_XV)
        SG_V_X_ = hashIT(TD_V,TD_X,P_XV, P_X , Cl , N_V,K_XV)
        try:
            assert SG_V_X == SG_V_X_
        except AssertionError:
            raise Exception("Signature Verification Failed")
        
    def _gen_session_keys(self,client ,P_XV, P_X , Cl , N_V):
        S_XV = xor(P_XV , self.hk_XV)
        C_X = (S_XV + 2*self.data.S_X) % self.p
        H_C_X = hashIT(C_X)
        try:
            assert H_C_X == self.data.HC_X
        except AssertionError:
            raise Exception("HC_X Verification Failed")
        
        R_X = self.puff(C_X)
        hr_X = hashIT(R_X)
        C_X_new = xor(xor(Cl, self.hk_XV), hr_X)
        R_X_new = self.puff(C_X_new)
        S_X_new  = xor(P_X , self.hk_XV)
        hk_XV_new = hashIT(self.K_XV, N_V)
        hr_X_new = hashIT(R_X_new)
        V1 = xor(R_X , self.hk_XV)
        V2 = xor(hr_X_new ,self.hk_XV)
        TD_X = hashIT(self.id,self.hk_XV)
        TD_V = hashIT(self.verifier_id,self.hk_XV)
        SG_XV = hashIT(TD_X,TD_V, N_V,V1,V2 , self.K_XV)
        K_S = xor(hr_X , hr_X_new)
        S_X = S_X_new
        self.data[client].C_XV = C_X
        N_X_new  = calcNonce()
        self.data[client].S_X = S_X_new
        self.data[client].HC_X = hashIT(C_X_new)
        return ( TD_X, TD_V , V1 , V2, N_X_new ,SG_XV)


        


class Device():
    def __init__(self, p: int, id: str):
        self.device_enroll = Device_enroll(p,id)
        self.data = self.device_enroll.data
        self.device_dd_ake = Device_DD_AKE(p,id,self.data)
        self.device_dv_ake = Device_DV_AKE(p,id,self.data)

    
    """    
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
    """
