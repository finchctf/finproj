import socket
import json
import pickle
from client import Device
from helper import Socket,recvSocket
import threading

DEBUG = False


class DeviceSocket(Socket):
    def __init__(self, host, port, p, id):
        super().__init__(host, port)
        self.host = host
        self.port = port
        self.device = Device(p, id)
        self.verifierID = ""

    def loopLogic(self,):
        while True:
            try:
                self._acceptConnection()
                data = self._recv()
                while self.handleData(data):
                    data = self._recv()
            except Exception as e:
                print(e)
                self._send(b"Error")
            finally:
                self.conn.close()

    def handleData(self, data):
        import pickle
        data = pickle.loads(data)
        self.ddAKE_DY(data)


    def makeConn(self,verifier_ip,verifier_port):
        self.recvSoc = recvSocket(verifier_ip,verifier_port)
    
    def sendRecv(self,data_type,data):
        import pickle
        self.recvSoc._send(pickle.dumps({
            "type": data_type,
            "verifierID": self.verifierID,
            "clientID": self.device.data.ID_X,
            "data": data
        }))
        data = self.recvSoc._recv()
        data = pickle.loads(data)
        if data["type"] == "exit":
            self.recvSoc._close()
            return False
        return data
        

    def enroll(self,verifier_ip,verifier_port):
        self.makeConn(verifier_ip,verifier_port)
        data=self.sendRecv("get_verifierID",{})
        if DEBUG:
            print("[+]  Data ",data)
        assert data["type"] == "verifierID"
        self.verifierID = data["verifierID"]
        if DEBUG:
            print("[+]  Verifier ID: ",self.verifierID)
        data={
            "verifierID": self.verifierID,
            "clientID": self.device.data.ID_X
        }
        #print("[-]  Data ",data)
        data=self.sendRecv("verifier_enroll_add_client",data)
        if DEBUG:
            print("[+]  Data ",data)
        assert data["type"] == "device_enroll_get_CX_CXV"
        C_X = data["data"]["C_X"]
        C_XV = data["data"]["C_XV"]
        self.device.device_enroll.get_CX_CXV(C_X,C_XV)
        RX,RXV = self.device.device_enroll.get_RX_RXV()
        data = {
            "deviceID": self.device.data.ID_X,
            "R_X": RX,
            "R_XV": RXV
        }
        data=self.sendRecv("verifier_enroll_update_Rvals",data)
        if DEBUG:
            print("[+]  Data ",data)
        assert data["type"] == "device_enroll_store_vVals"
        S_X = data["data"]["s_X"]
        HC_X = data["data"]["hc_X"]
        C_XV = data["data"]["C_XV"]
        ID_X = data["clientID"]
        self.device.device_enroll.store_vVals(ID_X,S_X,HC_X,C_XV)
        self.recvSoc._close()

    def ddAKE_init(self, verifier_ip, verifier_port, pair_id):
        self.makeConn(verifier_ip,verifier_port)
        temp_keys=self.device.device_dd_ake.gen_tempo_keys(pair_id,self.verifierID)
        data={
                "TD_X": temp_keys[0],
                "TD_V": temp_keys[1],
                "TD_pair": temp_keys[2],
                "n_X": temp_keys[3],
                "Sig_X_V": temp_keys[4],
                "pairID": pair_id,
                "verifierID": self.verifierID,
                "clientID": self.device.data.ID_X,
        }
        data=self.sendRecv("verifier_dd_ake_update_tempo_keys_and_gen",data)
        if DEBUG:
            print("[+]  Data ",data)
        assert data["type"] == "device_dd_ake_verify_and_gen_session_key"
        assert pair_id == data["pairID"]
        assert self.verifierID == data["verifierID"]
        self.pair_ip = data["pair_ip"]
        data = data["data"]
        session_key=self.device.device_dd_ake.verify_and_gen_session_key(
            data["TD_V"],data["TD_X"],data["D_X"],data["R_p"],data["nonceV"],data["SG_V_X"],data["flag"]
        )
        self.recvSoc._close()
        print("Success",session_key.hex())

    def ddAKE_DY(self,data):
        if DEBUG:
            print("[+]  Data ",data)
        assert data["verifierID"] == self.verifierID
        if data["type"] == "device_dd_ake_verify_and_gen_session_key":
            data = data["data"]
            session_key=self.device.device_dd_ake.verify_and_gen_session_key(
                data["TD_V"],data["TD_X"],data["D_X"],data["R_p"],data["nonceV"],data["SG_V_X"],data["flag"]
            )
            print("Success",session_key.hex())
            return False
        raise Exception("Invalid Data")


    def dvAKE_init(self, verifier_ip, verifier_port):
        temp_keys=self.device.device_dv_ake.gen_tempo_identity(self.verifierID)
        data={
                "TD_X": temp_keys[0],
                "TD_V": temp_keys[1],
                "nonceX": temp_keys[2],
                "Sig_X_V": temp_keys[3],
        }
        self.makeConn(verifier_ip,verifier_port)
        data=self.sendRecv("verifier_dv_ake_update_tempo_identity_and_gen",data)
        assert data["type"] == "device_dv_ake_verify_and_gen_session_key"
        assert self.verifierID == data["verifierID"]
        assert self.device.data.ID_X == data["clientID"]
        data = data["data"]
        datas,session_key=self.device.device_dv_ake.verify_and_gen_session_key(
            data["TD_V"],data["TD_X"],data["P_XV"],
            data["P_X"],data["Cl"],data["nonceV"],data["SG_XV"],self.verifierID
        )
        data = {
            #TD_X, TD_V , V1 , V2, Nonce_X ,SG_XV
            "TD_X": datas[0],
            "TD_V": datas[1],
            "V1": datas[2],
            "V2": datas[3],
            "nonceX": datas[4],
            "SG_XV": datas[5],

        }
        data=self.sendRecv("verifier_dv_ake_verify_and_gen_session_key",data)
        self.recvSoc._close()
        print("Success",session_key.hex())



    def handleThread(self,verifier_ip,verifier_port):
        self.enroll(verifier_ip,verifier_port)
        exitt = False
        k=input("""Enter your choice 
1.DD_AKE
2.DV_AKE
0.exit
""")
        while not exitt:
            if k == "1":
                pair_id = input("Pair ID: ")
                self.ddAKE_init(verifier_ip,verifier_port,pair_id)
            elif k == "2":
                device.dvAKE_init(verifier_ip,verifier_port)
            elif k == "0":
                exitt = True
            else:
                print("Invalid Choice")
            k=input("Enter your choice\n")
        device.conn.close()





        


if __name__ == "__main__":
    import sys
    p = 1212005173304576588776035408720434249624843017988539769573321072546946726998200133077605437
    id = sys.argv[2]
    host = "0.0.0.0"
    port = int(sys.argv[3])
    verifier_ip = "localhost" #input("Verifier IP: ")
    verifier_port = int(sys.argv[1]) #int(input("Verifier Port: "))
    device = DeviceSocket(host, port, p, id)
    thread1 = threading.Thread(target=device.loopLogic)
    thread1.start()
    thread2 = threading.Thread(target=device.handleThread,args=(verifier_ip,verifier_port))
    thread2.start()
    thread2.join()
    #force kill thread1
    thread1._stop()
    exit(0)


    
