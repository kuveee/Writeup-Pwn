#!/usr/bin/env python3
import os
def search(idx):
 i = str(idx)
 for directory in os.listdir():
    os.chdir(directory)
    for subdir in os.listdir():
        if subdir == idx:
            os.chdir('..')
            return directory # found
    os.chdir('..')
 return None # not found
if __name__ == '__main__':
    os.chdir('./.secret') # cd to .secret
    cnt = 1 # index to search for
    letter = ''
    while 1:
        letter = search(cnt) # directory that cnt was found in
        if letter is None: break
        print(letter, end='') # print with no \n at the end
        cnt += 1
