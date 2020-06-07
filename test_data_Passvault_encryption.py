# encoding:utf-8
# test data for unittest module test_Passvault_encryption

# encoded bytes

# b16decode(s, casefold=False)
# Decode the Base16 encoded bytes-like object or ASCII string s
# The result is returned as a bytes object.

KDF_SALT = 'A426668DFD750D3062BFA947F78C336F'
HMAC_SALT = 'A426668DFD750D3062BFA947F78C336F'
IV = 'FE7D7673787958BE864F355B9250CEB6'
PASSWORD_A = '00112233445566778899AABBCCDDEEFF'

KEYS = ('31CB8EBE07CD7ACED6474DFA280BEB01',
        'C3E70D3CA5A9E73668C1E685F4877FCF16EB39BBED97E9CC2DE182F8B7069BDB',
        '00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF',
        )

PASSWORD = b'secret'
PASSWORDS = ['secret', 'top secret', 'aaaaaaaa', '0000000000', '1w1w1w1w', '2294a191c4f234c0', 'aRRxqJ45zQo=', ' ', '.', 'p@s$VV0Rd']
PLAIN_TEXTS = ['Attack at down', 'attack at down', 'ATTACK AT DOWN', 'just another secret message', 'There is Tayler Darden?']
# test for byte data to be added
