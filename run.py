p = 89725685850239958443238402010853908314824152174340982259070258737678950396973

def device_enrollment():

    from core import Verifier,Device

    global vA,vB,dA,dB,p
    # Verifier
    vA = Verifier(p,"DeviceA")
    vB = Verifier(p,"DeviceB")

    # Device
    dA = Device(p, *vA.generate_challenge(), "DeviceA")
    dB = Device(p, *vB.generate_challenge(), "DeviceB")

    # Verifier
    vA.update_Rvals(*dA.get_RX_V())
    vB.update_Rvals(*dB.get_RX_V())

    # Device
    dA.update_vals(*vA.get_HC_S_X())
    dB.update_vals(*vB.get_HC_S_X())

    # Verifier
    print(vA.data)
    print(vB.data)

    # Device - TODO: Improve the output representation
    print(dA.data)
    print(dB.data)


def device_device_ake():
    pass


if __name__ == "__main__":
    device_enrollment()