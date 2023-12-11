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
        self.x = self.generate_qpu_output()

    def __call__(self,challenge):
        import random
        random.seed(self.x)
        kk= random.randint(challenge,self.P-1)
        #print("PUFF: ",challenge,kk)
        return kk

    def generate_qpu_output(self,qubits=5, measurements=1024):

        from qiskit import QuantumCircuit, Aer, execute

        circuit = QuantumCircuit(qubits, qubits)
        # Apply Hadamard gates to all qubits to create superposition
        circuit.h(range(qubits))
        # Measure all qubits
        circuit.measure(range(qubits), range(qubits))
        # Execute the circuit on a simulator
        simulator = Aer.get_backend('qasm_simulator')
        result = execute(circuit, simulator, shots=measurements).result()
        # Get the counts of each outcome
        counts = result.get_counts(circuit)
        t=0
        for key in counts:
            t+=pow(int(key,2),counts[key])
        return t

def hashIT(*args) -> bytes:
    from hashlib import sha256
    x=b"".join([i if type(i)==bytes else i.to_bytes((i.bit_length()+7)//8,"big") for i in args])
    return sha256(x).digest()
    



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



class Socket:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self._startServer()

    def _startServer(self):
        import socket
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind((self.host, self.port))
        self.s.listen(5)
        print("Server Listening")

    def _acceptConnection(self):
        self.conn, self.addr = self.s.accept()
        #print("Connected to ", self.addr)

    def _send(self, data):
        self.conn.sendall(data)
    
    def _recv(self):
        return self.conn.recv(1024)
    
    def _close(self):
        self.conn.close()
        self.s.close()

class recvSocket:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self._connect()

    def _connect(self):
        import socket
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((self.host, self.port))
        #print("Connected to ", self.host, self.port)

    def _send(self, data):
        self.s.sendall(data)
    
    def _recv(self):
        return self.s.recv(1024)
    
    def _close(self):
        self.s.close()