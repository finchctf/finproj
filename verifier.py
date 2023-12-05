from helper import *

class Verifier_enroll:
    def __init__(self,p:int,id:str,data:vStoreContainer):
        self.id = id
        self.p = p
        self.data = data
    
    def add_client(self,client: str):
        self.data[client] = vStore(ID_X=client)

    def generate_challenge(self,client: str):
        assert client in self.data
        #two seeds
        C_X, C_XV = [getRand(self.p) for _ in range(2)]
        data = vStore(ID_X=client)
        self.C_X, self.C_XV = C_X, C_XV
        self.data[client] = data
        return C_X,C_XV
    
    def update_Rvals(self,client: str,R_X,R_XV):
        assert client in self.data
        # data = self.data[client]
        self.R_X, self.R_XV = R_X, R_XV
        # self.data[client] = data

    def generate_shares(self,client: str):
        assert client in self.data
        R_AND = getRand(self.p)
        s_XV = (self.C_X + 2 * R_AND) % self.p
        s_X = (self.C_X + R_AND) % self.p
        hr_X = hashIT(self.R_X)
        hc_X = hashIT(self.C_X)
        K_XV = self.R_XV
        self.store(client,s_XV,hr_X,K_XV)
        return client, s_X, hc_X, self.C_XV

    def store(self,client: str,s_XV,hr_X,K_XV):
        data = self.data[client]
        data.S_XV = s_XV
        data.HR_X = hr_X
        data.K_XV = K_XV
        self.data[client] = data

class Verifier_DD_AKE():
    def __init__(self,data):
        self.data = data

    def update_tempo_keys_and_gen(self,client,TD_X,TD_V,TD_pair,n_X,Sig_X_V,pair_id,verifier_id):
        self._update_tempo_keys(client,TD_X,TD_V,TD_pair,n_X,Sig_X_V)
        return self._gen_tempo_keys(client,pair_id,verifier_id,TD_X,TD_V,TD_pair)
    
    def _update_tempo_keys(self,client,TD_X,TD_V,TD_pair,n_X,Sig_X_V):
        data = self.data[client]
        nonceX = float(n_X)
        try:
            assert float(calcNonce()) - nonceX < 60*5
        except AssertionError:
            raise Exception("Nonce Not Fresh")
        Sig_X_V_ = hashIT(TD_X,TD_V,TD_pair,n_X,data.K_XV)
        try:
            assert Sig_X_V == Sig_X_V_
        except AssertionError:
            raise Exception("Signature Verification Failed")
        
    def _gen_tempo_keys(self,client,pair_id,verifier_id,TD_X,TD_V,TD_pair):
        data_X = self.data[client]
        data_pair = self.data[pair_id]
        self.N_V = calcNonce()
        hK_XV = hashIT(data_X.K_XV,self.N_V)
        hK_YV = hashIT(data_pair.K_XV,self.N_V)
        R_p = xor(hashIT(data_X.HR_X,self.N_V),hashIT(data_pair.HR_X,self.N_V))
        #print("-"*35,hashIT(data_X.HR_X,self.N_V))
        D_X = data_X.S_XV ^ int.from_bytes(hK_XV,'big')
        D_Y = data_pair.S_XV ^ int.from_bytes(hK_YV,'big')
        SG_V_X = hashIT(TD_V,TD_X,D_X,R_p,self.N_V,data_X.K_XV)
        SG_V_Y = hashIT(TD_V,TD_pair,D_Y,R_p,self.N_V,data_pair.K_XV)
        return (TD_V,TD_X,D_X,R_p,self.N_V,SG_V_X),(TD_V,TD_pair,D_Y,R_p,self.N_V,SG_V_Y)

class Verifier_DV_AKE():
    def __init__(self,data,p):
        self.data = data
        self.p=p

    def update_tempo_keys_and_gen(self,client,TD_X,TD_V,n_X,Sig_X_V,verifier_id):
        self._update_tempo_keys(client,TD_X,TD_V,n_X,Sig_X_V)
        self.generate_challenge(client)
        return self.generate_shares(client,TD_V)

    def _update_tempo_keys(self,client,TD_X,TD_V,n_X,Sig_X_V):
        data = self.data[client]
        nonceX = float(n_X)
        try:
            assert float(calcNonce()) - nonceX < 60*5
        except AssertionError:
            raise Exception("Nonce Not Fresh")
        Sig_X_V_ = hashIT(TD_X,TD_V,n_X,data.K_XV)
        try:
            assert Sig_X_V == Sig_X_V_
        except AssertionError:
            raise Exception("Signature Verification Failed")

    def generate_challenge(self,client: str):
        assert client in self.data
        #one seed
        C_X_new = getRand(self.p)
        self.C_X_new = C_X_new 

    def generate_shares(self,client: str,TD_V:bytes):
        assert client in self.data
        R_AND_new = getRand(self.p)
        s_XV_new = (self.C_X_new + 2 * R_AND_new) % self.p
        s_X_new = (self.C_X_new + R_AND_new) % self.p
        # generate nonce V
        nonceV = calcNonce()
        # generate hk_XC
        hk_XV = hashIT(self.data[client].K_XV,nonceV)
        # retrieves hr_A
        hr_X = self.data[client].HR_X
        # generate P_XV =S_XV xor hk_XC
        P_XV = s_XV_new ^ int.from_bytes(hk_XV,'big')
        # generate P_X =S_X_NEW xor hk_XC
        P_X = s_X_new ^ int.from_bytes(hk_XV,'big')
        # Cl = C_X_new xor hk_XC xor hr_X
        Cl = self.C_X_new ^ int.from_bytes(hk_XV,'big') ^ int.from_bytes(hr_X,'big')
        TD_X = hashIT(client.encode(),hk_XV)
        SG_XV = hashIT(TD_V,TD_X,nonceV,P_XV,P_X,Cl,self.data[client].K_XV)
        return (TD_V,TD_X,nonceV,Cl,SG_XV)
    
    def verify_and_gen_session_key(self,client,TD_X,TD_V,nonceV,V1,V2 , N_X,SG_XV):
        self._verify_tempo_keys(client ,TD_V,TD_X,nonceV,V1,V2,SG_XV)
        return self._gen_session_keys()
    
    def _verify_tempo_keys(self,client,TD_V,TD_X,nonceV,V1 ,V2,SG_XV):
        nonceVX = float(nonceV)
        try:
            assert float(calcNonce()) - nonceVX < 60*5
        except AssertionError:
            raise Exception("Nonce Not Fresh")
        P_XV = xor(self.S_XV , self.hk_XV)
        SG_XV_ = hashIT(TD_V,TD_X,nonceV,V1, V2 ,self.data[client].K_XV)
        try:
            assert SG_XV == SG_XV_
        except AssertionError:
            raise Exception("Signature Verification Failed")
        
    def gen_session_key(self,client,TD_V,TD_X,V1,V2,nonceV):
        hr_X_new = xor(V2,self.hk_XV)
        hr_X = xor(V1,self.hk_XV)
        K_S = xor(hr_X , hr_X_new)

        
        
        
        

class Verifier():
    def __init__(self,p: int, id: str):
        self.p = p
        self.id = id
        self.data = vStoreContainer()
        self.verifier_enroll = Verifier_enroll(p,id,self.data)
        self.verifier_dd_ake = Verifier_DD_AKE(self.data)
        self.verifier_dv_ake = Verifier_DV_AKE(self.data,self.p)






    """
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
    """

