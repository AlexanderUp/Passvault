# encoding:utf-8
<<<<<<< HEAD
# auxiliary functions for aes ecb/cbc Monte-Carlo tests
=======
>>>>>>> f2f76a7a9975cd97df706b73af01288b76a81db7
# auxiliary functions for Passvault


import hashlib
<<<<<<< HEAD
import os
=======
>>>>>>> f2f76a7a9975cd97df706b73af01288b76a81db7


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

<<<<<<< HEAD
def pad_with_zeroes(block, block_lenght=32):
    if len(block) != block_lenght:
        block = '0' * (block_lenght - len(block)) + block
    return block

def make_average():
    x = 0
    count = 0
    def average(num):
        nonlocal x, count
        x += num
        count += 1
        return x / count
    return average


if __name__ == '__main__':
    print('*' * 125)
    average = make_average()
    print(average(10))
    print(average(20))
    print(average(30))

    if len(os.argv) > 1 and os.path.isfile(sys.argv[-1]):
        import sys
        file = sys.argv[-1]
        hash = get_hash(file)
        print('Test hashing...')
        print(f'File: {file}')
        print(f'Hash: {hash}')
=======

if __name__ == '__main__':
    print('*' * 125)
    import sys
    file = sys.argv[-1]
    hash = get_hash(file)
    print(f'File: {file}')
    print(f'Hash: {hash}')
>>>>>>> f2f76a7a9975cd97df706b73af01288b76a81db7
