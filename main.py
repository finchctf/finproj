import hashlib
import random

# p, randA
p = 1606938044258990275541962092341162602522202993782792835301376
RandA = random.randint(1, p - 1)

CA = random.randint(1, p - 1)
CAV = random.randint(1, p - 1)

# PUF
def PUFA(challenge):
    return (challenge + RandA) % p

RA = PUFA(CA)
RAV = PUFA(CAV)

sAV = (CA + 2 * RandA) % p
## sA = CA + RandA mod p
sA = (CA + 2 * RandA) % p

def H(data):
    return hashlib.sha256(str(data).encode()).hexdigest()

hrA = H(RA)
hcA = H(CA)

IDA = "DeviceA"  

KAV = RAV

message_to_deviceA = (IDA, sA, hcA, CAV)

device_informationA = (IDA, sA, hcA, CAV)

verifier_informationA = (IDA, sAV, hrA, KAV)


print("DeviceA Information:", device_informationA)
print("Verifier Information:", verifier_informationA)

NA = random.randint(1, 100000) 

RandB = random.randint(1, p - 1)


CB = random.randint(1, p - 1)
CBV = random.randint(1, p - 1)


def PUFB(challenge):
    return (challenge + RandB) % p

RB = PUFB(CB)
RBV = PUFB(CBV)

sBV = (CB + 2 * RandB) % p
sB = (CB + 2 * RandB) % p

def H(data):
    return hashlib.sha256(str(data).encode()).hexdigest()

hrB = H(RB)
hcB = H(CB)

IDB = "DeviceB" 

KBV = RBV

message_to_deviceB = (IDB, sB, hcB, CBV)

device_informationB = (IDB, sB, hcB, CBV)

verifier_informationB = (IDB, sBV, hrB, KBV)

print("DeviceB Information:", device_informationB)
print("Verifier Information:", verifier_informationB)

KAV = PUFA(CAV)

hkAV = H(KAV + str(NA).encode()).hexdigest()

TDA = H(IDA + hkAV)
TDV = H("IDV" + hkAV) 
TDB = H(IDB + hkAV)

SGAV = H(TDA + TDV + TDB + str(NA).encode() + KAV)

message_to_verifier = (TDA, TDV, TDB, NA, SGAV)
