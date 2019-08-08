# encoding:utf-8
# auxiliary function for aes ecb/cbc Monte-Carlo tests


def pad_with_zeroes(block, block_lenght=32):
    if len(block) != block_lenght:
        block = '0' * (block_lenght - len(block)) + block
    return block

def make_average():
    pass
