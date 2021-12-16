import setuptools
from python_settings import settings

import python_utils
import random
import re
import utils
import hashlib

# import optimized_curve
# from charm.toolbox.pairinggroup import PairingGroup
# import newjson
bn128 = settings.getBn128()
lib = bn128
FQ, FQ2, FQ12, field_modulus = lib.FQ, lib.FQ2, lib.FQ12, lib.field_modulus
pairing, G1, G2, G12, b, b2, b12, is_inf, is_on_curve, eq, add, double, curve_order, multiply = \
    lib.pairing, lib.G1, lib.G2, lib.G12, lib.b, lib.b2, lib.b12, lib.is_inf, lib.is_on_curve, lib.eq, lib.add, lib.double, lib.curve_order, lib.multiply


def merge_dicts(*dict_args):
    """
    Given any number of dicts, shallow copy and merge into a new dict,
    precedence goes to key value pairs in latter dicts.
    """
    result = {}
    for dictionary in dict_args:
        result.update(dictionary)
    return result


def FQ12ToInt(fq12value, g=None):
    # (2421572130728995776966111225896962453619921797707709996809563916572643662968, 17597669113497198503743549746221204610554807092054855309459603004045023729206, 6808099643203508867535121604680299872213567506732374554311995409561205588434, 20025038805775319672168534746658411053237712056380191928175913333560165995460, 229731873704813733254464584553986182279125791426847734113154846709141667703, 15164045160012650235884986075993103685827469362115071397686828810584571044239, 20589711274383952032836025308858471335299207129121936034661870760293858608322, 10736647173781131293519746348193571250385196827748347896963402121636455740763, 3562776870626562607436017013136855967750414971220044562927491099632443892614, 15469551818407474514163670492590988300440249779914596449375411725189831980606, 21562754573273249085847279209463097911104658328348822858012614416489264329871, 2936009288700626504404857756638695686919241885607318830341540210932700674080)
    return [g ** FQ12.coeffs[i] for i in range(0, FQ12.degree)]


def gPowFQ12(h, fq12, mod=field_modulus):
    return [h ** int(fq12.coeffs[i]) for i in range(0, fq12.degree)]


def minusFQ12(fq121, fq122):
    return [int(fq121.coeffs[i] - fq122.coeffs[i]) for i in range(0, fq121.degree)]


def hash(str):
    x = hashlib.sha256()
    x.update(str.encode())
    return x.hexdigest()


def hash2(str):
    x = hashlib.sha256()
    x.update((str + "2").encode())
    return x.hexdigest()


def powFQ12(g, fq12):
    # for i in range(0,fq12.degree):
    #   print(fq12.coeffs[i])
    return [g ** fq12.coeffs[i] for i in range(0, fq12.degree)]


def multiplyEta(eta, hz):
    return [eta[i] * hz for i in range(0, len(eta))]




class MaabeRW15():

    def __init__(self):
        # ABEncMultiAuth.__init__(self)
        # self.group = group

        self.abeutils = utils()

        return

    def random(self):
        # return 2
        return int(random.random() * (2 ** 256)) % curve_order

    def unpack_attribute(self, attribute):
        parts = re.split(r"[@_]", attribute)
        assert len(parts) > 1, "No @ char in [attribute@authority] name"
        # print(parts[0], parts[1])
        return parts[0], parts[1], None if len(parts) < 3 else parts[2]

    def setup(self):
        g1 = multiply(G2, self.random())
        g2 = multiply(G1, self.random())
        # print("example g2",multiply(g1,self.random()))
        egg = (g1, g2)
        # egg=multiply(G12,self.random())
        # print(egg)
        H = lambda x: utils.hashToG1(x)
        F = lambda x: utils.hashToG1(x)
        # print(H("123"),F("123"))
        # print(type(g1[0]))
        # print(type(gp[""]))
        gp = {'g1': g1, 'g2': g2, 'egg': egg, 'H': H, 'F': F, 'h': FQ(int(2 ** 256 * random.random()) % field_modulus),
              'j': FQ(int(2 ** 256 * random.random()) % field_modulus),
              'k': FQ(int(2 ** 256 * random.random()) % field_modulus)}
        if debug:
            print("Global Setup=========================")
            print(gp["egg"])
            print("\n")
        return gp

    def authsetup(self, gp, name):
        """
        Setup an attribute authority.
        :param gp: The global parameters
        :param name: The name of the authority
        :return: The public and private key of the authority
        """
        alpha, y = self.random(), self.random()
        # egga = multiply(gp['egg'], alpha)
        egga = (gp['g1'], multiply(gp['g2'], alpha))  # gp['egg'] ** alpha

        # gy={}
        gy = multiply(gp['g1'], y)
        g2y = multiply(gp['g2'], y)
        # print("11111111")
        # print(type(gy["g1"][0]),type(gp["g1"][0]))
        # print(is_on_curve(gy, b2))
        # print(is_on_curve(egga, b12))
        pk = {'name': name, 'egga': egga, 'gy': gy, 'g2y': g2y}
        sk = {'name': name, 'alpha': alpha, 'y': y}
        if debug:
            print("Authsetup: =======================%s" % name)
            print(pk)
            print(sk)

        return pk, sk

    def keygen(self, gp, sk, gid, attribute):
        """
        Generate a user secret key for the attribute.
        :param gp: The global parameters.
        :param sk: The secret key of the attribute authority.
        :param gid: The global user identifier.
        :param attribute: The attribute.
        :return: The secret key for the attribute for the user with identifier gid.
        """
        _, auth, _ = self.unpack_attribute(attribute)
        assert sk['name'] == auth, "Attribute %s does not belong to authority %s" % (attribute, sk['name'])

        t = self.random()
        # print(multiply(gp['g2'],sk['alpha']))

        r = multiply(gp['H'](gid), sk['y'])
        # print(type(r[0]))
        # print(multiply(gp['F'](attribute), t))
        # K = gp['g2'] ** sk['alpha'] * gp['H'](gid) ** sk['y'] * gp['F'](attribute) ** t
        # KP = gp['g1'] ** t
        k1 = multiply(gp['g2'], sk['alpha'])
        k2 = multiply(gp['H'](gid), sk['y'])
        k3 = multiply(gp['F'](attribute), t)
        # print(type(k1[0]),type(k2[0]))
        K = add(k1, k2)
        K = add(K, k3)
        # K = add(\
        #     add(multiply(gp['g2'],sk['alpha']),\
        #         	multiply(gp['H'](gid), sk['y'])),\
        #     multiply(gp['F'](attribute), t))
        # print("........",is_on_curve(K, b))
        # KP = gp['g1'] ** t
        KP = multiply(gp['g1'], t)
        # print("11111111",is_on_curve(KP, b2))

        if debug:
            print("Keygen")
            print("User: %s, Attribute: %s" % (gid, attribute))
            print({'K': K, 'KP': KP})

        return {'K': K, 'KP': KP}

    def multiple_attributes_keygen(self, gp, sk, gid, attributes):
        """
        Generate a dictionary of secret keys for a user for a list of attributes.
        :param gp: The global parameters.
        :param sk: The secret key of the attribute authority.
        :param gid: The global user identifier.
        :param attributes: The list of attributes.
        :return: A dictionary with attribute names as keys, and secret keys for the attributes as values.
        """
        uk = {}
        for attribute in attributes:
            uk[attribute] = self.keygen(gp, sk, gid, attribute)
        return uk

    def encrypt(self, gp, pks, message, policy_str):
        z = self.random()  # secret to be shared
        zp = self.random()  # secret to be shared
        w = 0  # 0 to be shared
        wp = 0

        policy = self.abeutils.createPolicy(policy_str)
        attr_list = self.abeutils.getAttributeList(policy)
        attribute_list = self.abeutils.getAttributeList(policy)
        # print("policy",policy,"attribute_list", attribute_list)
        secret_shares = self.abeutils.calculateSharesDict(z, policy)  # These are correctly set to be exponents in Z_p
        zero_shares = self.abeutils.calculateSharesDict(w, policy)
        # print(secret_shares)

        secret_sharesp = self.abeutils.calculateSharesDict(zp, policy)  # These are correctly set to be exponents in Z_p
        zero_sharesp = self.abeutils.calculateSharesDict(wp, policy)

        M = message
        Mp = (gp['g1'], multiply(gp['g2'], self.random()))  # gp["egg"]**self.random()
        # print(type(M))
        # C0 = (gp['egg'] ** z) * M
        C0 = (gp['g1'], add(multiply(gp['g2'], z), M[1]))
        # C0p= (gp['egg'] ** zp) * Mp
        C0p = (gp['g1'], add(multiply(gp['g2'], zp), Mp[1]))

        C1, C2, CHat2, C3, CHat3, C4 = {}, {}, {}, {}, {}, {}
        C1p, C2p, CHat2p, C3p, CHat3p, C4p = {}, {}, {}, {}, {}, {}
        tx, txp = {}, {}
        cp = int(hash2(str(C0) + "||" + str(C1) + "||" + str(C2) + "||" + str(C3) + "||" + str(C4)), 16) % curve_order
        # cp=1
        ztilde = (zp - cp * z) % curve_order  # for egg
        # ztilde2 is used for interpolate check
        # ztilde2=(zp-cp*z)
        Mtilde = add(Mp[1], multiply(M[1], (curve_order - cp) % curve_order))  # %curve_order#egg
        # print(C0p[1])
        # print(add(Mtilde, multiply(gp['egg'][1],ztilde)))
        # print(multiply(C0[1],cp))
        # assert(eq(C0p[1], add(add(Mtilde, multiply(gp['egg'][1],ztilde)), multiply(C0[1],cp))))
        # print("123456")
        txhat, secret_shareshat, zero_shareshat = {}, {}, {}
        # secret_shareshat2,zero_shareshat2={},{}
        a = [0]
        for i in attribute_list:
            attribute_name, auth, _ = self.unpack_attribute(i)
            attr = "%s@%s" % (attribute_name, auth)

            tx[i] = self.random()
            C1[i] = (gp['g1'], add(multiply(gp['egg'][1], secret_shares[i]), multiply(pks[auth]['egga'][1], tx[i])))
            C2[i] = multiply(gp['g1'], (curve_order - tx[i]))
            CHat2[i] = multiply(gp['g2'], (curve_order - tx[i]))
            C3[i] = add(multiply(pks[auth]['gy'], tx[i]), multiply(gp['g1'], zero_shares[i]))
            CHat3[i] = add(multiply(pks[auth]['g2y'], tx[i]), multiply(gp['g2'], zero_shares[i]))
            C4[i] = multiply(gp['F'](attr), tx[i])

            txp[i] = self.random()
            C1p[i] = (gp['g1'], add(multiply(gp['egg'][1], secret_sharesp[i]), multiply(pks[auth]['egga'][1], txp[i])))
            C2p[i] = multiply(gp['g1'], (curve_order - txp[i]))
            CHat2p[i] = multiply(gp['g2'], (curve_order - txp[i]))
            C3p[i] = add(multiply(pks[auth]['gy'], txp[i]), multiply(gp['g1'], int(zero_sharesp[i])))
            CHat3p[i] = add(multiply(pks[auth]['g2y'], txp[i]), multiply(gp['g2'], int(zero_sharesp[i])))
            C4p[i] = multiply(gp['F'](attr), txp[i])
            # print("",pairing(gp['g1'], CHat2p[i]), pairing(C2p[i], gp["g2"]))

            # assert(pairing(gp['g1'], CHat2p[i]) == pairing(C2p[i], gp["g2"]))

            txhat[i] = (txp[i] - cp * tx[i]) % curve_order
            secret_shareshat[i] = (secret_sharesp[i] - cp * secret_shares[i]) % curve_order
            # secret_shareshat2[i]=(secret_sharesp[i]-cp*secret_shares[i])
            zero_shareshat[i] = (zero_sharesp[i] - cp * zero_shares[i]) % curve_order
            # zero_shareshat2[i]=(zero_sharesp[i]-cp*zero_shares[i])
            a.append(secret_shares[i])
            # assert(eq(C1p[i][1], add(\
            #                     add(multiply(gp['egg'][1],(secret_shareshat[i]%curve_order)), \
            #                         multiply(pks[auth]['egga'][1],(txhat[i]))),\
            #                     multiply(C1[i][1], (cp%curve_order)))))
            # print("C1 "+attr+" check, passed")
            # assert(eq(C2p[i],add(multiply(gp['g1'], (-txhat[i]) %curve_order), multiply(C2[i], cp))))
            # print("C2 "+attr+" check, passed")
            # assert(eq(C3p[i],\
            #     add(add(multiply(pks[auth]['gy'], txhat[i]), \
            #             multiply(gp['g1'], zero_shareshat[i])),\
            #         multiply(C3[i],cp))))
            # assert(pairing(gp['g1'], CHat3p[i]) == pairing(C3p[i], gp["g2"]))
            # print("C3 "+attr+" check, passed")
            # assert(eq(C4p[i],add(multiply(gp['F'](attr), txhat[i]), multiply(C4[i], cp))))
            # print("C4 "+attr+" check, passed")

        # y=self.abeutils.recoverCoefficients([1, 2])
        # print(a,y)
        # zp = int((a[1]*y[1]+a[2]*y[2])%bn128.curve_order)
        # print(zp)
        # # assert(z==zp)

        # y=self.abeutils.recoverCoefficients([2, 3])
        # print(a,y)
        # zp = int((a[3]*y[3]+a[2]*y[2])%bn128.curve_order)
        # print(zp)

        # y=self.abeutils.recoverCoefficients([1, 2, 3])
        # print(a,y)
        # zp = int((a[1]*y[1]+ a[3]*y[3]+a[2]*y[2])%bn128.curve_order)
        # print(zp)

        c = int(hash(str(C0) + "||" + str(C1) + "||" + str(C2) + "||" + str(C3) + "||" + str(C4)), 16) % curve_order
        quotient = [0 for i in range(0, 12)]
        dkg_pk = [0 for i in range(0, 12)]
        dkg_pkp = [0 for i in range(0, 12)]
        # eta=[0 for i in range(0,12)]
        # etap=[0 for i in range(0,12)]

        Mppairing = pairing(Mp[0], Mp[1])
        Mpairing = pairing(M[0], M[1])
        Mhat = (Mppairing - c * Mpairing)
        zhat = (zp - c * z) % (field_modulus - 1)
        h = gp["h"]
        k = gp["k"]
        j = gp["j"]
        for i in range(0, len(quotient)):
            dkg_pk[i] = h ** (int(Mpairing.coeffs[i]))
            dkg_pkp[i] = h ** (int(Mppairing.coeffs[i]))
            Mppairing_M = int(Mppairing.coeffs[i]) - c * int(Mpairing.coeffs[i])
            quotient[i] = int((Mppairing_M - int(Mhat.coeffs[i])) // field_modulus) % (field_modulus - 1)
            # assert(dkg_pkp[i] == h**(int(Mhat.coeffs[i]))* h**(quotient[i])* dkg_pk[i]**c )
            # eta[i]=j ** (int(Mpairing.coeffs[i])) * k ** z
            # etap[i]=j ** (int(Mppairing.coeffs[i])) * k ** zp
            # assert(etap[i] == j**(int(Mhat.coeffs[i])) * j**quotient[i] * k**zhat * eta[i]**c )
            # print(j**quotient[i])
        # print({'policy': policy_str, 'C0': C0, 'C1': C1, 'C2': C2, 'C3': C3, 'C4': C4})
        return {'policy': policy_str, 'attr_list': attr_list, 'C0': C0, 'C1': C1, 'C2': C2, 'CHat2': CHat2, 'C3': C3,
                'CHat3': CHat3, 'C4': C4,
                'C0p': C0p, 'C1p': C1p, 'C2p': C2p, 'CHat2p': CHat2p, 'C3p': C3p, 'CHat3p': CHat3p, 'C4p': C4p,
                # "Mppairing":Mppairing,
                "txhat": txhat,
                "secret_shareshat": secret_shareshat,
                # "secret_shareshat2":secret_shareshat2,
                "zero_shareshat": zero_shareshat,
                # "zero_shareshat2":zero_shareshat2,
                "c": c,
                "cp": cp,
                "ztilde": ztilde,
                # "ztilde2":ztilde2,
                "Mtilde": Mtilde,
                "dkg_pk": dkg_pk,
                "dkg_pkp": dkg_pkp,
                "h": gp["h"],
                "k": gp["k"],
                "j": gp["j"],
                # "eta":eta,
                # "etap":etap,
                "Mhat": Mhat,
                "zhat": zhat,
                "quotient": quotient,  # element in FQ12 are in [0, field_modulus-1], the divi
                }

    def aggregateCT(self, gp, ct1, ct2):

        ct = {}
        policy_str = ct1['policy']
        if ct1['policy'] != ct2['policy']:
            print("policy not equal!! cannot divide")
            return
        C0 = [gp['g1'], add(ct1['C0'][1], ct2['C0'][1])]
        C0p = [gp['g1'], add(ct1['C0p'][1], ct2['C0p'][1])]
        policy = self.abeutils.createPolicy(policy_str)
        attribute_list = self.abeutils.getAttributeList(policy)

        C1, C2, C3, C4, C1p, C2p, C3p, C4p = {}, {}, {}, {}, {}, {}, {}, {}
        for i in attribute_list:
            attribute_name, auth, _ = self.unpack_attribute(i)
            attr = "%s@%s" % (attribute_name, auth)
            C1[i] = [gp['g1'], {}]
            C1[i][1] = add(ct1['C1'][i][1], ct2['C1'][i][1])
            C2[i] = add(ct1['C2'][i], ct2['C2'][i])
            C3[i] = add(ct1['C3'][i], ct2['C3'][i])
            C4[i] = add(ct1['C4'][i], ct2['C4'][i])

            C1p[i] = [gp['g1'], {}]
            C1p[i][1] = add(ct1['C1p'][i][1], ct2['C1p'][i][1])
            C2p[i] = add(ct1['C2p'][i], ct2['C2p'][i])
            C3p[i] = add(ct1['C3p'][i], ct2['C3p'][i])
            C4p[i] = add(ct1['C4p'][i], ct2['C4p'][i])
        # print(C4p,ct1['C4p'])
        return {'policy': policy_str, 'C0': C0, 'C1': C1, 'C2': C2, 'C3': C3, 'C4': C4, 'C0p': C0p, 'C1p': C1p,
                'C2p': C2p, 'C3p': C3p, 'C4p': C4p}

    def decrypt(self, gp, sk, ct):
        # print(ct)
        policy = self.abeutils.createPolicy(ct['policy'])
        # coefficients = self.abeutils.newGetCoefficients(policy)
        pruned_list = self.abeutils.prune(policy, sk['keys'].keys())
        coefficients = self.abeutils.newGetCoefficients(policy, pruned_list)
        # print(pruned_list)
        # print(coefficients)
        if not pruned_list:
            raise Exception("You don't have the required attributes for decryption!")

        B = FQ12([1] + [0] * 11)
        Bp = FQ12([1] + [0] * 11)

        for i in range(len(pruned_list)):
            x = pruned_list[i].getAttribute()  # without the underscore
            y = pruned_list[i].getAttributeAndIndex()  # with the underscore
            exp = int(coefficients[y])
            if exp < 0:
                exp += curve_order
            # print("C4,",ct['C4'], y in ct['C4'])
            a = pairing(ct['C2'][y], sk['keys'][x]['K'])
            b = pairing(ct['C3'][y], gp['H'](sk['GID']))
            c = pairing(sk['keys'][x]['KP'], ct['C4'][y])
            B = B * ((pairing(ct['C1'][y][0], ct['C1'][y][1]) * a * b * c) ** exp)

            a = pairing(ct['C2p'][y], sk['keys'][x]['K'])
            b = pairing(ct['C3p'][y], gp['H'](sk['GID']))
            c = pairing(sk['keys'][x]['KP'], ct['C4p'][y])
            Bp = Bp * ((pairing(ct['C1p'][y][0], ct['C1p'][y][1]) * a * b * c) ** exp)
        # print("B===",B)
        if debug:
            print("Decrypt")
            print("SK:")
            print(sk)
            print("Decrypted Message:")
            print(pairing(ct['C0'][0], ct['C0'][1]) / B)
        # print(ct["C0"]/B == ct["C0p"]/Bp)
        # print(type(pairing(ct['C0'][0],ct['C0'][1]) / B))
        return pairing(ct['C0'][0], ct['C0'][1]) / B


debug = False
if __name__ == '__main__':
    maabe = MaabeRW15()
    gp = maabe.setup()
    (pk1, sk1) = maabe.authsetup(gp, "UT")
    # print(pk, sk)
    user_attributes1 = ['STUDENT@UT', 'PHD1@UT', 'PHD2@UT', 'PHD3@UT', 'PHD4@UT', 'PHD5@UT', 'PHD6@UT', 'PHD7@UT',
                        'PHD8@UT', 'PHD9@UT']
    user_keys1 = maabe.multiple_attributes_keygen(gp, sk1, "bob", user_attributes1)
    # print(user_keys1)

    (pk2, sk2) = maabe.authsetup(gp, "OU")
    user_attributes2 = ['STUDENT@OU', 'PHD1@OU', 'PHD2@OU', 'PHD3@OU', 'PHD4@OU', 'PHD5@OU', 'PHD6@OU', 'PHD7@OU',
                        'PHD8@OU', 'PHD9@OU']
    user_keys2 = maabe.multiple_attributes_keygen(gp, sk2, "bob", user_attributes2)
    # print(user_keys2)

    (pk3, sk3) = maabe.authsetup(gp, "TO")
    user_attributes3 = ['STUDENT@TO']
    user_keys3 = maabe.multiple_attributes_keygen(gp, sk3, "bob", user_attributes3)
    # print(user_keys2)

    public_keys = {'UT': pk1, 'OU': pk2, 'TO': pk3}
    # private_keys = {'UT': sk1, 'OU': sk2}
    # access_policy = '(2 of (STUDENT@UT, PROFESSOR@OU, (XXXX@UT or PHD@UT))) and (STUDENT@UT or MASTERS@OU)'
    access_policy = '(2 of (STUDENT@UT, STUDENT@OU, STUDENT@TO))'
    # access_policy = 'STUDENT@UT and STUDENT@OU'
    # access_policy = 'STUDENT@UT'
    # access_policy = 'STUDENT@OU'
    message = (gp['g1'], multiply(gp['g2'], maabe.random()))  # gp["egg"]**maabe.random()
    print("message", pairing(message[0], message[1]))
    cipher_text = maabe.encrypt(gp, public_keys, message, access_policy)
    print("ciphertext", cipher_text)
    user_keys = {'GID': "bob", 'keys': merge_dicts(user_keys1, user_keys2)}
    decrypted_message = maabe.decrypt(gp, user_keys, cipher_text)
    print(user_keys)
    print("decrypted_message", decrypted_message)

    print(decrypted_message == pairing(message[0], message[1]))











