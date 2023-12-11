import socket
import json
import pickle
from verifier import Verifier
from helper import Socket,recvSocket

DEBUG = False

class VerifierSocket(Socket):
    def __init__(self, host, port, p, id):
        super().__init__(host, port)
        self.verifier = Verifier(p, id)
        self.clients = {}
        self.loopLogic()

    def loopLogic(self):
        while True:
            try:
                iter = 0
                self._acceptConnection()
                data = self._recv()
                while self.handleData(data):
                    iter += 1
                    if DEBUG:
                        print("[+] Iteration: ",iter)
                    data = self._recv()
            except Exception as e:
                #print trackback also for the error if DEBUG is True
                if DEBUG:
                    import traceback
                    traceback.print_exc()
                print(repr(e))
                import pickle
                self._send(pickle.dumps({
                    "type": "exit",
                    "code": "error"
                }))
            finally:
                self.conn.close()

    def handleData(self, data):
        import pickle
        data = pickle.loads(data)
        if data["type"] == "get_verifierID":
            self._send(pickle.dumps({
                "verifierID": self.verifier.id,
                "type": "verifierID"
            }))
            return True
        assert data["verifierID"] == self.verifier.id
        if data["type"] == "verifier_enroll_add_client":
            if DEBUG:
                print("[+] Data: ",data)
            if data["clientID"] not in self.clients:
                self.clients[data["clientID"]] = self.addr[0]
                self.verifier.verifier_enroll.add_client(data["clientID"])
                C_X, C_XV = self.verifier.verifier_enroll.generate_challenge(data["clientID"])
                self._send(pickle.dumps({
                    "verifierID": self.verifier.id,
                    "clientID": data["clientID"],   
                    "type": "device_enroll_get_CX_CXV",
                    "data": {
                        "C_X": C_X,
                        "C_XV": C_XV
                    }
                }))
                return True
        assert data["clientID"] in self.clients
        if data["type"] == "verifier_enroll_update_Rvals":
            clientID = data["clientID"]
            data = data["data"]
            data["clientID"] = clientID
            if DEBUG:
                print("[+] Data: ",data)
            self.verifier.verifier_enroll.update_Rvals(data["clientID"],data["R_X"],data["R_XV"])
            shares = self.verifier.verifier_enroll.generate_shares(data["clientID"])
            data = {
                "clientID": shares[0],
                "s_X": shares[1],
                "hc_X": shares[2],
                "C_XV": shares[3]
            }
            data = {
                "verifierID": self.verifier.id,
                "clientID": data["clientID"],
                "type": "device_enroll_store_vVals",
                "data": data
            }
            self._send(pickle.dumps(data))
            return False
        elif data["type"] == "verifier_dd_ake_update_tempo_keys_and_gen":
            data = data["data"]
            if DEBUG:
                print("[++] Data: ",data)
            temp_keys = self.verifier.verifier_dd_ake.update_tempo_keys_and_gen(data["clientID"],data["TD_X"],data["TD_V"],data["TD_pair"],data["n_X"],data["Sig_X_V"],data["pairID"],data["verifierID"])
            data1 = {
                "verifierID": self.verifier.id,
                "clientID": data["clientID"],
                "pair_ip": self.clients[data["pairID"]],
                "pairID": data["pairID"],
                "type": "device_dd_ake_verify_and_gen_session_key",
                "data": {
                    "TD_V": temp_keys[0][0],
                    "TD_X": temp_keys[0][1],
                    "D_X": temp_keys[0][2],
                    "R_p": temp_keys[0][3],
                    "nonceV": temp_keys[0][4],
                    "SG_V_X": temp_keys[0][5],
                    "flag": True
                }
            }
            self._send(pickle.dumps(data1))
            #print("success1")
            data2 = {
                "verifierID": self.verifier.id,
                "clientID": data["pairID"],
                "type": "device_dd_ake_verify_and_gen_session_key",
                "data": {
                    "TD_V": temp_keys[1][0],
                    "TD_X": temp_keys[1][1],
                    "D_X": temp_keys[1][2],
                    "R_p": temp_keys[1][3],
                    "nonceV": temp_keys[1][4],
                    "SG_V_X": temp_keys[1][5],
                    "flag": False
                }
            }
            #print(self.clients[data["pairID"]])
            DY_SOC = recvSocket(self.clients[data["pairID"]], 5000)
            DY_SOC._send(pickle.dumps(data2))
            DY_SOC._close()
            #print("success2")
            return False
        elif data["type"] == "verifier_dv_ake_update_tempo_identity_and_gen":
            clientID = data["clientID"]
            data = data["data"]
            temp_keys=self.verifier.verifier_dv_ake.update_tempo_identity_and_gen(
                clientID,data["TD_X"],data["TD_V"],data["nonceX"],data["Sig_X_V"],self.verifier.id
            )
            data = {
                "verifierID": self.verifier.id,
                "clientID": clientID,
                "type": "device_dv_ake_verify_and_gen_session_key",
                "data": {
                    "TD_V": temp_keys[0],
                    "TD_X": temp_keys[1],
                    "P_XV": temp_keys[2],
                    "P_X": temp_keys[3],
                    "Cl": temp_keys[4],
                    "nonceV": temp_keys[5],
                    "SG_XV": temp_keys[6]
                }
            }
            self._send(pickle.dumps(data))
            return True
        elif data["type"] == "verifier_dv_ake_verify_and_gen_session_key":
            clientID = data["clientID"]
            data = data["data"]
            if DEBUG:
                print("[+] Data: ",data)
            session_key=self.verifier.verifier_dv_ake.verify_and_gen_session_key(
                clientID,data["TD_X"],data["TD_V"],data["V1"],data["V2"],data["nonceX"],data["SG_XV"]
                )
            self._send(pickle.dumps({
                "type": "exit",
                "code": "success"
            }))
            print("Success",session_key.hex())
            return False




if __name__ == "__main__":
    import sys
    p = 1212005173304576588776035408720434249624843017988539769573321072546946726998200133077605437
    id = "v1"
    host = "0.0.0.0"
    port = int(sys.argv[1])
    #print(port)
    verifier = VerifierSocket(host, port, p, id)