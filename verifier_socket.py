import socket
import json
from verifier import Verifier

class VerifierSocket:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.verifier = Verifier(1212005173304576588776035408720434249624843017988539769573321072546946726998200133077605437, "V1")

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen()
            print(f"Verifier is listening on {self.host}:{self.port}")
            conn, addr = s.accept()
            with conn:
                print("Connected by", addr)
                client_id = "A"  
                self.verifier.verifier_enroll.add_client(client_id)  
                self.enrollment_phase(conn)
                self.device_device_ake(conn)  # Added DD-AKE communication

    def enrollment_phase(self, conn):
        client_id = "A"  #
        C_X, C_XV = self.verifier.verifier_enroll.generate_challenge(client_id)
        challenges = {"C_X": C_X, "C_XV": C_XV}
        conn.sendall(json.dumps(challenges).encode())
        responses_json = conn.recv(1024).decode()
        responses = json.loads(responses_json)
        RA, RAV = responses["RA"], responses["RAV"]

        self.verifier.verifier_enroll.update_Rvals("A", RA, RAV)
        shares = self.verifier.verifier_enroll.generate_shares("A")
        message = {"ID": "A", "s_A": shares[1], "hc_A": shares[2].decode("latin-1"), "CAV": shares[3]}
        conn.sendall(json.dumps(message).encode())

        print(f"Sent message to the device.")

        verification_result = conn.recv(1024).decode()
        print(f"Verification result from Device: {verification_result}")

    def device_device_ake(self, conn):
        temp_keys_B_json = conn.recv(1024).decode()
        temp_keys_B = json.loads(temp_keys_B_json)
        temp_keys_B = tuple(temp_keys_B)

        temp_keys_V = self.verifier.verifier_dd_ake.update_tempo_keys_and_gen("A", *temp_keys_B, "B", "V1")
        conn.sendall(json.dumps(temp_keys_V).encode())

def main():
    verifier_socket = VerifierSocket(host="localhost", port=8000)
    verifier_socket.start()

if __name__ == "__main__":
    main()
