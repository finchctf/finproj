p = 89725685850239958443238402010853908314824152174340982259070258737678950396973

def device_enrollment():

    from util import Verifier,Device

    global verifier,devices,p

    # Verifier
    verifier = Verifier(p,"V1")
    [verifier.add_client(i) for i in "A B".split()]

    # Device
    devices = {i:Device(p, *verifier.generate_challenge(i), i) for i in "A B".split()}

    # Verifier
    [verifier.update_Rvals(i,*devices[i].get_RX_V()) for i in "A B".split()]

    # Device
    [devices[i].store_vVals(*verifier.get_HC_S_X(i)) for i in "A B".split()]

    # Verifier
    print("Verifier")
    print(str(verifier.data["A"]))
    print(str(verifier.data["B"]))

    # Device - TODO: Improve the output representation
    print("Devices")
    print(str(devices["A"].data))
    print(str(devices["B"].data))

def device_device_ake():
    
    # Device A -> Device B
    temp_keys_A=devices["A"].gen_tempo_keys("B","V1")

    temp_keys_V=verifier.update_tempo_keys_and_gen("A",*temp_keys_A,"B","V1")

    sig1=devices["A"].verify_and_gen_session_key(*temp_keys_V[0])

    sig2=devices["B"].verify_and_gen_session_key(*temp_keys_V[1],False)






