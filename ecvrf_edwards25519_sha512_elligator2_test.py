# Copyright (C) 2020 Eric Schorn, NCC Group Plc; Provided under the MIT License

import random  # Intentionally deterministic
import sys

if sys.version_info[0] != 3 or sys.version_info[1] < 7:
    print("Requires Python v3.7+")
    sys.exit()

import ecvrf_edwards25519_sha512_elligator2


# Section A.4. ECVRF-EDWARDS25519-SHA512-Elligator2
# All three test cases taken verbatim from document

print("# Test 1 ...", end='')
test_dict = dict()
sk = bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
test_dict['public_key_y'] = bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
alpha_string = b''  # (the empty string)
test_dict['secret_scalar_x'] = bytes.fromhex('307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f')
test_dict['r'] = bytes.fromhex('9ddd071cd5837e591a3a40c57a46701bb7f49b1b53c670d490c2766a08fa6e3d')
test_dict['w'] = bytes.fromhex('c7b5d6239e52a473a2b57a92825e0e5de4656e349bb198de5afd6a76e5a07066')
test_dict['e'] = (ecvrf_edwards25519_sha512_elligator2.PRIME - 1).to_bytes(32, 'little')  # -1
test_dict['h'] = bytes.fromhex('1c5672d919cc0a800970cd7e05cb36ed27ed354c33519948e5a9eaf89aee12b7')
test_dict['k'] = bytes.fromhex('868b56b8b3faf5fc7e276ff0a65aaa896aa927294d768d0966277d94599b7afe4a6330770da5fdc2875121e0cbecbffbd4ea5e491eb35be53fa7511d9f5a61f2')
test_dict['k_b'] = bytes.fromhex('c4743a22340131a2323174bfc397a6585cbe0cc521bfad09f34b11dd4bcf5936')
test_dict['u'] = bytes.fromhex('c4743a22340131a2323174bfc397a6585cbe0cc521bfad09f34b11dd4bcf5936')
test_dict['k_h'] = bytes.fromhex('e309cf5272f0af2f54d9dc4a6bad6998a9d097264e17ae6fce2b25dcbdd10e8b')
test_dict['v'] = bytes.fromhex('e309cf5272f0af2f54d9dc4a6bad6998a9d097264e17ae6fce2b25dcbdd10e8b')
test_dict['pi_string'] = bytes.fromhex('b6b4699f87d56126c9117a7da55bd0085246f4c56dbc95d20172612e9d38e8d7ca65e573a126ed88d4e30a46f80a666854d675cf3ba81de0de043c3774f061560f55edc256a787afe701677c0f602900')
test_dict['beta_string'] = bytes.fromhex('5b49b554d05c0cd5a5325376b3387de59d924fd1e13ded44648ab33c21349a603f25b84ec5ed887995b33da5e3bfcb87cd2f64521c4c62cf825cffabbe5d31cc')
ecvrf_edwards25519_sha512_elligator2.test_dict = test_dict

p_status, pi_result = ecvrf_edwards25519_sha512_elligator2.ecvrf_prove(sk, alpha_string)
assert p_status == "VALID" and pi_result == test_dict['pi_string']
b_status, beta_result = ecvrf_edwards25519_sha512_elligator2.ecvrf_proof_to_hash(pi_result)
assert b_status == "VALID" and beta_result == test_dict['beta_string']
Y = ecvrf_edwards25519_sha512_elligator2.get_public_key(sk)
valid_result, valid_beta = ecvrf_edwards25519_sha512_elligator2.ecvrf_verify(Y, pi_result, alpha_string)
assert valid_result == "VALID"
assert valid_beta == beta_result
print("pass\n")


print("# Test 2 ...", end='')
test_dict = dict()
sk = bytes.fromhex('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb')
test_dict['public_key_y'] = bytes.fromhex('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c')
alpha_string = bytes([0x72])  # (1 byte)
test_dict['secret_scalar_x'] = bytes.fromhex('68bd9ed75882d52815a97585caf4790a7f6c6b3b7f821c5e259a24b02e502e51')
test_dict['r'] = bytes.fromhex('92181bd612695e464049590eb1f9746750d6057441789c9759af8308ac77fd4a')
test_dict['w'] = bytes.fromhex('7ff6d8b773bfbae57b2ab9d49f9d3cb7d9af40a03d3ed3c6beaaf2d486b1fe6e')
test_dict['e'] = int(1).to_bytes(32, 'little')
test_dict['h'] = bytes.fromhex('86725262c971bf064168bca2a87f593d425a49835bd52beb9f52ea59352d80fa')
test_dict['k'] = bytes.fromhex('fd919e9d43c61203c4cd948cdaea0ad4488060db105d25b8fb4a5da2bd40e4b8330ca44a0538cc275ac7d568686660ccfd6323c805b917e91e28a4ab352b9575')
test_dict['k_b'] = bytes.fromhex('04b1ba4d8129f0d4cec522b0fd0dff84283401df791dcc9b93a219c51cf27324')
test_dict['u'] = bytes.fromhex('04b1ba4d8129f0d4cec522b0fd0dff84283401df791dcc9b93a219c51cf27324')
test_dict['k_h'] = bytes.fromhex('ca8a97ce1947d2a0aaa280f03153388fa7aa754eedfca2b4a7ad405707599ba5')
test_dict['v'] = bytes.fromhex('ca8a97ce1947d2a0aaa280f03153388fa7aa754eedfca2b4a7ad405707599ba5')
test_dict['pi_string'] = bytes.fromhex('ae5b66bdf04b4c010bfe32b2fc126ead2107b697634f6f7337b9bff8785ee111200095ece87dde4dbe87343f6df3b107d91798c8a7eb1245d3bb9c5aafb093358c13e6ae1111a55717e895fd15f99f07')
test_dict['beta_string'] = bytes.fromhex('94f4487e1b2fec954309ef1289ecb2e15043a2461ecc7b2ae7d4470607ef82eb1cfa97d84991fe4a7bfdfd715606bc27e2967a6c557cfb5875879b671740b7d8')
ecvrf_edwards25519_sha512_elligator2.test_dict = test_dict

p_status, pi_result = ecvrf_edwards25519_sha512_elligator2.ecvrf_prove(sk, alpha_string)
assert p_status == "VALID" and pi_result == test_dict['pi_string']
b_status, beta_result = ecvrf_edwards25519_sha512_elligator2.ecvrf_proof_to_hash(pi_result)
assert b_status == "VALID" and beta_result == test_dict['beta_string']
Y = ecvrf_edwards25519_sha512_elligator2.get_public_key(sk)
valid_result, valid_beta = ecvrf_edwards25519_sha512_elligator2.ecvrf_verify(Y, pi_result, alpha_string)
assert valid_result == "VALID"
assert valid_beta == beta_result
print("pass\n")


print("# Test 3 ...", end='')
test_dict = dict()
sk = bytes.fromhex('c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7')
test_dict['public_key_y'] = bytes.fromhex('fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025')
alpha_string = bytes.fromhex('af82')  # (2 bytes)
test_dict['secret_scalar_x'] = bytes.fromhex('909a8b755ed902849023a55b15c23d11ba4d7f4ec5c2f51b1325a181991ea95c')
test_dict['r'] = bytes.fromhex('dcd7cda88d6798599e07216de5a48a27dcd1cde197ab39ccaf6a906ae6b25c7f')
test_dict['w'] = bytes.fromhex('2ceaa2c2ff3028c34f9fbe076ff99520b925f18d652285b4daad5ccc467e523b')
test_dict['e'] = (ecvrf_edwards25519_sha512_elligator2.PRIME - 1).to_bytes(32, 'little')  # -1
test_dict['h'] = bytes.fromhex('9d8663faeb6ab14a239bfc652648b34f783c2e99f758c0e1b6f4f863f9419b56')
test_dict['k'] = bytes.fromhex('8f675784cdc984effc459e1054f8d386050ec400dc09d08d2372c6fe0850eaaa50defd02d965b79930dcbca5ba9222a3d99510411894e63f66bbd5d13d25db4b')
test_dict['k_b'] = bytes.fromhex('d6f8a95a4ce86812e3e50febd9d48196b3bc5d1d9fa7b6dfa33072641b45d029')
test_dict['u'] = bytes.fromhex('d6f8a95a4ce86812e3e50febd9d48196b3bc5d1d9fa7b6dfa33072641b45d029')
test_dict['k_h'] = bytes.fromhex('f77cd4ce0b49b386e80c3ce404185f93bb07463600dc14c31b0a09beaff4d592')
test_dict['v'] = bytes.fromhex('f77cd4ce0b49b386e80c3ce404185f93bb07463600dc14c31b0a09beaff4d592')
test_dict['pi_string'] = bytes.fromhex('dfa2cba34b611cc8c833a6ea83b8eb1bb5e2ef2dd1b0c481bc42ff36ae7847f6ab52b976cfd5def172fa412defde270c8b8bdfbaae1c7ece17d9833b1bcf31064fff78ef493f820055b561ece45e1009')
test_dict['beta_string'] = bytes.fromhex('2031837f582cd17a9af9e0c7ef5a6540e3453ed894b62c293686ca3c1e319dde9d0aa489a4b59a9594fc2328bc3deff3c8a0929a369a72b1180a596e016b5ded')
ecvrf_edwards25519_sha512_elligator2.test_dict = test_dict

p_status, pi_result = ecvrf_edwards25519_sha512_elligator2.ecvrf_prove(sk, alpha_string)
assert p_status == "VALID" and pi_result == test_dict['pi_string']
b_status, beta_result = ecvrf_edwards25519_sha512_elligator2.ecvrf_proof_to_hash(pi_result)
assert b_status == "VALID" and beta_result == test_dict['beta_string']
Y = ecvrf_edwards25519_sha512_elligator2.get_public_key(sk)
valid_result, valid_beta = ecvrf_edwards25519_sha512_elligator2.ecvrf_verify(Y, pi_result, alpha_string)
assert valid_result == "VALID"
assert valid_beta == beta_result
print("pass\n")



##############
# A few negative tests
print("# Negative tests ...", end='')
for index in range(5):
    test_dict = dict()
    ecvrf_edwards25519_sha512_elligator2.test_dict = test_dict
    sk = random.getrandbits(256).to_bytes(32, 'little')
    alpha_string = random.getrandbits(256).to_bytes(32, 'little')
    Y = ecvrf_edwards25519_sha512_elligator2.get_public_key(sk)
    p_status, pi_string = ecvrf_edwards25519_sha512_elligator2.ecvrf_prove(sk, alpha_string)
    b_status, beta_string = ecvrf_edwards25519_sha512_elligator2.ecvrf_proof_to_hash(pi_string)
    valid_result, valid_beta = ecvrf_edwards25519_sha512_elligator2.ecvrf_verify(Y, pi_string, alpha_string)
    assert p_status == "VALID" and b_status == "VALID" and valid_result == "VALID" and valid_beta == beta_string

    bad_pi = bytearray(pi_string)
    bad_pi[-1] = int(bad_pi[-1] ^ 0x01)
    bad_beta = ecvrf_edwards25519_sha512_elligator2.ecvrf_proof_to_hash(bad_pi)
    valid_result, valid_beta = ecvrf_edwards25519_sha512_elligator2.ecvrf_verify(Y, bad_pi, alpha_string)
    assert valid_result == "INVALID"
    print(index, end='')
print(" pass\n")



##############
# The following code can be used to generate 'random' test vectors to aid porting, e.g.
#
# python3 ecvrf_edwards25519_sha512_elligator2_test.py > random_test.py
# python3 random_test.py
#

print("# The following values can be output to file then run")
print("import ecvrf_edwards25519_sha512_elligator2, random")

for index in range(3):
    print("# Testcase {}\n".format(index))
    test_dict = dict()
    print("test_dict = dict()")
    ecvrf_edwards25519_sha512_elligator2.test_dict = test_dict
    print("ecvrf_edwards25519_sha512_elligator2.test_dict = test_dict")
    sk = random.getrandbits(256).to_bytes(32, 'little')
    print("sk = bytes.fromhex('{}')".format(sk.hex()))
    alpha_string = random.getrandbits(256).to_bytes(32, 'little')
    print("alpha_string = bytes.fromhex('{}')".format(alpha_string.hex()))

    Y = ecvrf_edwards25519_sha512_elligator2.get_public_key(sk)
    p_status, pi_string = ecvrf_edwards25519_sha512_elligator2.ecvrf_prove(sk, alpha_string)

    b_status, beta_string = ecvrf_edwards25519_sha512_elligator2.ecvrf_proof_to_hash(pi_string)
    valid_result, valid_beta = ecvrf_edwards25519_sha512_elligator2.ecvrf_verify(Y, pi_string, alpha_string)
    assert p_status == "VALID" and b_status == "VALID" and valid_beta == beta_string

    keys = sorted(test_dict.keys())
    for key in keys:
        print("test_dict['{}'] = bytes.fromhex('{}')".format(key.replace('_sample', ''), test_dict[key].hex()))

    print("\nY = ecvrf_edwards25519_sha512_elligator2.get_public_key(sk)")
    print("p_status, pi_string = ecvrf_edwards25519_sha512_elligator2.ecvrf_prove(sk, alpha_string)")
    print("b_status, beta_string = ecvrf_edwards25519_sha512_elligator2.ecvrf_proof_to_hash(pi_string)")
    print("valid_result, valid_beta = ecvrf_edwards25519_sha512_elligator2.ecvrf_verify(Y, pi_string, alpha_string)")
    print("assert p_status == \"VALID\" and b_status == \"VALID\" and valid_beta == beta_string")
    print("print('test {} PASSED')".format(index))
    print("\n\n")
