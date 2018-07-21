# encoding:utf-8
# tests for password module

print('=' * 75)

try:
    import password
except ImportError:
    print('Can\'t load required modules!')
    sys.exit()
else:
    print('Import successfull (module test_password)!')


def test_init_encrypted_enc_key(_password, enc_key):
    print('Testing init_encrypted_enc_key function...')
    print('enc_key:\n{}'.format(enc_key))
    f = password.Entry()
    encrypted_enc_key = f.init_encrypted_enc_key(_password, enc_key) # enc_key encrypted by password returned
    print('Encrypted enc_key:\n{}'.format(encrypted_enc_key))
    print('Testing decryption...')
    encrypted_enc_key = f.pre_decrypt_data(encrypted_enc_key)
    assert isinstance(encrypted_enc_key, bytes)
    enc_key = f.decrypt_enc_key(_password, encrypted_enc_key)
    print('Decrypted enc_key:\n{}'.format(enc_key))
    print('Remove padding...')
    enc_key = f.post_decrypt_data(enc_key)
    print('Padding removed:\n{}'.format(enc_key))
    return enc_key

def test_init_vault_id():
    pass

def test_connect_to_vault():
    a = password.Entry()
    conn, cur = a.connect_to_vault()
    print(conn, cur)
    cur.close()
    conn.close()
    print('Connection closed!')

def test_enc_key_decryption():
    a = password.Entry()
    conn, cur = a.connect_to_vault()
    enc_key = a.password_decrypt(conn, cur)
    print('key: {}'.format(enc_key))
    return None

def test_change_password():
    a = password.Entry()
    conn, cur = a.connect_to_vault()
    a.change_password(conn, cur)
    return None

def test_create_entry():
    a = password.Entry()
    conn, cur = a.connect_to_vault()
    enc_key = a.password_decrypt(conn, cur)
    return a.create_entry(conn, cur, enc_key)

def test_get_entry_key():
    a = password.Entry()
    conn, cur = a.connect_to_vault()
    enc_key = a.password_decrypt(conn, cur)
    id_ = input('Enter entry id...\n>>> ')
    entry_key = a.get_entry_key(conn, cur, id_, enc_key)
    return entry_key

def test_update_entry():
    fields = ('group_id', 'account_name', 'login', 'url', 'memo')
    a = password.Entry()
    conn, cur = a.connect_to_vault()
    enc_key = a.password_decrypt(conn, cur)
    id_ = input('Entry id of entry to be updated...\n>>> ')
    print('Choose fields which you want to update....')
    data = {}
    for field in fields:
        answer = input('Do you want to update field "{}"? Y/N\n>>> '.format(field))
        if answer.lower() == 'y':
            data[field] = input('Input new value...\n>>> ')
        else:
            data[field] = None
    # print('New values:')
    # for key in data.keys():
    #     print('{}: {}'.format(key, data[key]))
    return a.update_entry(conn, cur, id_, enc_key, data)

def test_delete_entry():
    a = password.Entry()
    conn, cur = a.connect_to_vault()
    id_ = input('Enter id of string to be deleted... \n>>> ')
    return a.delete_entry(conn, cur, id_)

def test_get_list_of_entries():
    a = password.Entry()
    conn, cur = a.connect_to_vault()
    return a.get_list_of_entries(conn, cur)

def test_update_password():
    a = password.Entry()
    conn, cur = a.connect_to_vault()
    return a.update_password(conn, cur, id_=3)

def test_cleanup():
    a = password.Entry()
    conn, cur = a.connect_to_vault()
    return a.cleanup(conn, cur)



if __name__ == '__main__':
    print('=' * 75)
    # t = password.Entry()
    # enc_key = t.get_random_key()
    # decrypted_enc_key = test_init_encrypted_enc_key(_password='qwerty', enc_key=enc_key)
    # assert enc_key == decrypted_enc_key
    # test_connect_to_vault()
    # test_enc_key_decryption()
    # test_change_password()
    # test_create_entry()
    # v = test_get_entry_key()
    # print('key: {}'.format(v))
    # test_update_entry()
    # test_delete_entry()
    # test_get_list_of_entries()
    # test_update_password()
    test_cleanup()
