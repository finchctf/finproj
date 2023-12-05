from helper import *
class Device_enroll:
    def __init__(self, p:int ,id:str,data):
        self.id = id
        self.p = p
        self.puff = PUFF(self.p)
        self.data = data

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

    def gen_tempo_identity(self,verifier_id: str):
        K_XV = self.puff(self.data.C_XV)
        nonceX = calcNonce()
        hk_XV = hashIT(K_XV,nonceX)
        TD_X = hashIT(self.id,hk_XV)
        TD_V = hashIT(verifier_id.encode(),hk_XV)
        Sig_X_V = hashIT(TD_X+TD_V+nonceX,K_XV)
        return TD_X,TD_V,nonceX,Sig_X_V
    
    def verify_and_gen_session_key(self,TD_V,TD_X,P_XV, P_X , Cl , N_V , SG_V_X,verifier_id):
        self._verify_tempo_keys(TD_V,TD_X,P_XV, P_X , Cl , N_V , SG_V_X)
        return self._gen_session_keys(P_XV, P_X , Cl , N_V,verifier_id)

    def _verify_tempo_keys(self,TD_V,TD_X,P_XV, P_X , Cl , N_V , SG_V_X):
        nonceVX = float(N_V)
        try:
            assert float(calcNonce()) - nonceVX < 60*5
        except AssertionError:
            raise Exception("Nonce Not Fresh")
        K_XV = self.puff(self.data.C_XV)
        SG_V_X_ = hashIT(TD_V,TD_X,P_XV, P_X , Cl , N_V,K_XV)
        #print("*",TD_V,TD_X,P_XV, P_X , Cl , N_V,K_XV,sep="\n")

        try:
            assert SG_V_X == SG_V_X_
        except AssertionError:
            raise Exception("Signature Verification Failed")
        
    def _gen_session_keys(self ,P_XV, P_X , Cl , N_V,verifier_id):
        K_XV = self.puff(self.data.C_XV)
        hk_XV = hashIT(K_XV,N_V)
        #print("*",hk_XV)
        S_XV = int.from_bytes(xor(P_XV , hk_XV),"big")
        #print("*",S_XV,P_XV,hk_XV,sep="\n")
        C_X = (2*self.data.S_X - S_XV ) % self.p
        #print(C_X)
        H_C_X = hashIT(C_X)
        try:
            assert H_C_X == self.data.HC_X
        except AssertionError:
            raise Exception("HC_X Verification Failed")
        
        R_X = self.puff(C_X)
        hr_X = hashIT(R_X)
        #print(type(Cl),type(hk_XV),type(hr_X),sep="\n")
        C_X_new = Cl ^ int.from_bytes(hk_XV,"big") ^ int.from_bytes(hr_X,"big")
        R_X_new = self.puff(C_X_new)
        S_X_new  = xor(P_X , hk_XV)
        Nonce_X = calcNonce()
        hk_XV = hashIT(K_XV, Nonce_X)
        hr_X_new = hashIT(R_X_new)
        V1 = xor(R_X , hk_XV)
        V2 = xor(hr_X_new ,hk_XV)
        TD_X = hashIT(self.id,hk_XV)
        TD_V = hashIT(verifier_id.encode(),hk_XV)
        SG_XV = hashIT(TD_X,TD_V,V1,V2 ,Nonce_X, K_XV)
        self.K_S = xor(hr_X , hr_X_new) 
        self.data.S_X = S_X_new       
        self.data.C_XV = C_X
        self.data.HC_X = hashIT(C_X_new)
        print(self.K_S)
        return TD_X, TD_V , V1 , V2, Nonce_X ,SG_XV


        


class Device():
    def __init__(self, p: int, id: str):
        self.data = dStore(ID_X=id)
        self.device_enroll = Device_enroll(p,id,self.data)
        self.device_dd_ake = Device_DD_AKE(p,id,self.data)
        self.device_dv_ake = Device_DV_AKE(p,id,self.data)
