p = 89725685850239958443238402010853908314824152174340982259070258737678950396973

def device_enrollment():

    from verifier import Verifier
    from client import Device

    global verifier,dA,dB,p

    # Verifier
    verifier = Verifier(p,"V1")
    verifier.verifier_enroll.add_client("A")
    
    # Device A
    dA = Device(p,"A")
    dA.device_enroll.get_CX_CXV(*verifier.verifier_enroll.generate_challenge("A"))

    # Verifier
    verifier.verifier_enroll.update_Rvals("A",*dA.device_enroll.get_RX_RXV())

    # Device A
    dA.device_enroll.store_vVals(*verifier.verifier_enroll.generate_shares("A"))

    print(str(verifier.data["A"]))
    print(str(dA.data))

    # Verifier
    verifier.verifier_enroll.add_client("B")

    # Device B
    dB = Device(p,"B")
    dB.device_enroll.get_CX_CXV(*verifier.verifier_enroll.generate_challenge("B"))

    # Verifier
    verifier.verifier_enroll.update_Rvals("B",*dB.device_enroll.get_RX_RXV())

    # Device B
    dB.device_enroll.store_vVals(*verifier.verifier_enroll.generate_shares("B"))

    print(str(verifier.data["B"]))
    print(str(dB.data))

def device_device_ake():
    
    # Device A -> Device B
    temp_keys_A=dA.device_dd_ake.gen_tempo_keys("B","V1")
    #temp_keys_B=devices["B"].gen_tempo_keys("A","V1")

    temp_keys_V=verifier.verifier_dd_ake.update_tempo_keys_and_gen("A",*temp_keys_A,"B","V1")
    #print(temp_keys_V)

    print(dA.device_dd_ake.verify_and_gen_session_key(*temp_keys_V[0]))
    print(dB.device_dd_ake.verify_and_gen_session_key(*temp_keys_V[1],False))

    # s1=devices["A"].verify_and_gen_session_key(*temp_keys_V[0])

    # s2=devices["B"].verify_and_gen_session_key(*temp_keys_V[1],False)
    # print(s1.hex(),s2.hex())


def device_verifier_ake():

    # Device A -> Verifier
    temp_keys_A=dA.device_dv_ake.gen_tempo_keys("V1")


    temp_keys_V=verifier.verifier_dv_ake.update_tempo_keys_and_gen("A",*temp_keys_A,"V1")
    print(temp_keys_V)




