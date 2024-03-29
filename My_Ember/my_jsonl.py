#!/usr/bin/env python
# coding: utf-8

# In[43]:


import pefile
from os import listdir
from os.path import isfile, isdir, join
import string
import numpy as np
import re
import math
import sys
from matplotlib.pyplot import hist
import matplotlib.pyplot as plt
import jsonlines

def strings(filename, min=5):
    with open(filename, errors="ignore") as f:  # Python 3.x
        result = ""
        for c in f.read():
            if c in string.printable:
                result += c
                continue
            if len(result) >= min:
                yield result
            result = ""
        if len(result) >= min:  # catch result at EOF
            yield result


# # General
# has_resources
# 
# symbols
# 
# size
# 
# exports
# 
# has_signature
# 
# has_debug
# 
# has_tls
# 
# vsize
# 
# imports
# 
# has_relocations

def gen_general(mypath):   
    gg = 0
    arr = []
    for qq in range(1):
        dic = {}
        gg += 1
        if gg > 50:
            break
        try:
            fullpath = mypath
            pe = pefile.PE(fullpath)
            dic = {}

            # number of imported and exported function

            try:
                count = 0
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        count += 1
                dic['imports'] = count
            except:
                dic['imports'] = 0

            try:
                count = 0
                for entry in pe.DIRECTORY_ENTRY_EXPORT:
                    for imp in entry.imports:
                        count += 1
                dic['exports'] = count
            except:
                dic['exports'] = 0

            # size and virtual size

            vsize = 0
            size = 0
            for section in pe.sections:
                vsize += section.Misc_VirtualSize
                size += section.SizeOfRawData
            dic['vsize'] = vsize
            dic['size'] = size

            # Debug sections or not
            try:
                tmp = pe.DIRECTORY_ENTRY_DEBUG
                dic['has_debug'] = 1
            except:
                dic['has_debug'] = 0

            # signature
            try:
                tmp = pe.VS_FIXEDFILEINFO[0].Signature
                dic['has_signature'] = 1
            except:
                dic['has_signature'] = 0

            # Resource

            try:
                tmp = pe.DIRECTORY_ENTRY_RESOURCE
                dic['has_resources'] = 1
            except:
                dic['has_resources'] = 0

            # TLS

            try:
                tmp = pe.DIRECTORY_ENTRY_TLS
                dic['has_tls'] = 1
            except:
                dic['has_tls'] = 0

            # relocations

            try:
                tmp = pe.DIRECTORY_ENTRY_BASERELOC
                dic['has_relocations'] = 1
            except:
                dic['has_relocations'] = 0

            # number of symbol QQ

            dic['symbols'] = 0

            arr.append(dic)

        except:
            continue
    #general = arr[0]
    return arr[0]

def gen_strings(mypath):    
    npsl = []
    for qq in range(1):
        fullpath = mypath
        sl = list(strings(fullpath))
        npsl.append(sl)
    # MZ
    num = 0
    MZ = 0
    for obj in npsl[num]:
        if 'MZ' in obj:
            MZ += 1

    # avglength

    tl = 0
    for obj in npsl[num]:
        tl += len(obj)
    avlength = tl/len(npsl[num])
    
    #numstrings

    numstrings = len(npsl[num])
    
    # urls

    urls = 0
    for obj in npsl[num]:
        if 'https://' in obj or 'http://' in obj:
            urls += 1
    
    # paths

    paths = 0
    for obj in npsl[num]:
        if 'C:\\' == obj[0:3] or 'D:\\' == obj[0:3]:
            paths += 1
    
    # printables

    printables = 0
    for obj in npsl[num]:
        n = len(obj)
        for i in range(n-5):
            if obj[i:(i+5)].isprintable():
                printables += 1
                break
    

    # entropy

    a = ''.join(npsl[num])


    def entropys(string):
            "Calculates the Shannon entropy of a string"

            # get probability of chars in string
            prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]

            # calculate the entropy
            entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])

            return entropy
    entropy = entropys(npsl[num])

    # printabledist

    printablehist = []
    for obj in npsl[num]:
        n = len(obj)
        for i in range(n-5):
            if obj[i:(i+5)].isprintable():
                printablehist.append((obj))
                break
    printabledist = hist(printablehist,96)[0]

    # registry

    registry = 0
    for obj in npsl[num]:
        if 'HKEY_ ' in obj:
            registry += 1
            
    # make dictionary
    strs = {}

    title = ['MZ',
    'avlength',
    'entropy',
    'numstrings',
    'paths',
    'printabledist',
    'printables',
    'registry',
    'urls']

    strs['MZ'] = MZ
    strs['avlength'] = avlength
    strs['entropy'] = entropy
    strs['numstrings'] = numstrings
    strs['paths'] = paths
    strs['printabledist'] = list(printabledist)
    strs['printables'] = printables
    strs['registry'] = registry
    strs['urls'] = urls
    return strs

def gen_hist(mypath):    
    content = bytearray(open(mypath, 'rb').read())
    freq, bins, patches = plt.hist(content, 256)
    #histogram = freq
    return list(freq)

def gen_ie(mypath):    
    pe = pefile.PE(mypath)
    imports = {}
    exports = {}
    try:
        for imp in pe.DIRECTORY_ENTRY_IMPORT:
            imports[(imp.dll).decode('ascii')] = []
            for entry in imp.imports:
                imports[(imp.dll).decode('ascii')].append((entry.name).decode('ascii'))
    except:
        print('OMG, no imports table QQ!!!')

    try:
        for exp in pe.DIRECTORY_ENTRY_EXPORT:
            exports[(exp.dll).decode('ascii')] = []
            for entry in exp.exports:
                exports[(exp.dll).decode('ascii')].append((entry.name).decode('ascii'))
    except:
        exports = []
    return imports, exports


# In[55]:


def gen_total(mypath):    
    total = {}

    total['general'] = gen_general(mypath)
    total['strings'] = gen_strings(mypath)
    total['histogram'] = gen_hist(mypath)
    total['imports'], total['exports'] = gen_ie(mypath)
    return total


# In[57]:


if __name__ == '__main__':
    json_save = []
    argc = len(sys.argv)
    df = True
    for i in range(1, argc):
        if isdir(sys.argv[i]):
            df = False
        
    if df:
        for i in range(1,argc):
            mypath = sys.argv[i]
            tmp = gen_total(mypath)
            json_save.append(tmp)
        with jsonlines.open('output.jsonl', mode='w') as writer:
            writer.write(json_save)
    elif (not df) and argc == 2:
        fpath = sys.argv[1]
        files = listdir(fpath)
        for f in files:
            mypath = fpath + '/' + f
            tmp = gen_total(mypath)
            json_save.append(tmp)
        with jsonlines.open('output.jsonl', mode='w') as writer:
            writer.write(json_save)
    else:
        print("\nPlease enter files' name seperated by space or a direction name ! \n")

