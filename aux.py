# encoding:utf-8
# auxiliary functions for Passvault


import hashlib


BLOCK_SIZE = 1024 * 1024 # one megabyte


def get_hash(file, block_size = BLOCK_SIZE):
    with open(file, 'br') as f:
        hasher = hashlib.sha256()
        while True:
            binary_content = f.read(block_size)
            if binary_content:
                hasher.update(binary_content)
            else:
                break
    return hasher.hexdigest()


if __name__ == '__main__':
    print('*' * 125)
    import sys
    file = sys.argv[-1]
    hash = get_hash(file)
    print(f'File: {file}')
    print(f'Hash: {hash}')
