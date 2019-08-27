# encoding:utf-8
# auxiliary function for aes ecb/cbc Monte-Carlo tests


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
