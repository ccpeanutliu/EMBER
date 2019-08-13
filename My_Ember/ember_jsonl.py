#!/usr/bin/env python
# coding: utf-8

# In[19]:


import pefile
import os
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
import hashlib
import time


# In[65]:


from scipy import stats
import pandas as pd

def Entropy(labels, base=2):
    # 计算概率分布
    probs = pd.Series(labels).value_counts() / len(labels)
    # 计算底数为base的熵
    en = stats.entropy(probs, base=base)
    return en


# In[2]:


def strings(filename, min=5):
    with open(filename, errors="ignore") as f:  # Python 3.x
    # with open(filename, "rb") as f:           # Python 2.x
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


# In[3]:


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


# # Strings

# In[81]:


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
            #print(obj)

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
            print(obj)

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


# # Histogram

# In[5]:


def gen_hist(mypath):    
    content = bytearray(open(mypath, 'rb').read())
    freq, bins, patches = plt.hist(content, 256)
    #histogram = freq
    return list(freq)


# # Combine

# output = []
# keys_strings = ['avlength', 'numstrings', 'registry', 'urls', 'MZ', 'printables', 'entropy', 'paths', 'printabledist']
# keys_general = ['exports', 'has_resources', 'imports', 'symbols', 'has_signature', 'has_relocations', 'has_debug', 'vsize', 'size', 'has_tls']
# for obj in range(1):
#     feature_num = []
#     for i in range(3):
#         feature_num.append([])
#     for j in keys_strings:
#         if j != 'printabledist':
#             feature_num[0].append(strs[j])
#         else:
#             for k in range(96):
#                 feature_num[0].append(strs[j][k])
#     for i in range(256):
#         feature_num[1].append(histogram[i])
#     for i in keys_general:
#         feature_num[2].append(general[i])
#     for i in range(256 - 104):
#         feature_num[0].append(0)
#     for i in range(256 - 10):
#         feature_num[2].append(0)
#     output.append(feature_num)

# In[6]:


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
        print('no imports table QQ!!!')

    try:
        for exp in pe.DIRECTORY_ENTRY_EXPORT:
            exports[(exp.dll).decode('ascii')] = []
            for entry in exp.exports:
                exports[(exp.dll).decode('ascii')].append((entry.name).decode('ascii'))
    except:
        exports = []
        print('no exports table QQ!!!')
    return imports, exports


# In[12]:


def gen_sha256(mypath):
    # Python program to find SHA256 hash string of a file

    filename = mypath
    sha256_hash = hashlib.sha256()
    with open(filename,"rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
        sha = sha256_hash.hexdigest()
    return sha


# In[31]:


def gen_appeared(mypath):
    appeared = time.ctime(os.path.getctime(mypath))
    month = appeared[4:7]
    year = appeared[-4:]
    if month == 'Jan':
        month = "01"
    elif month == 'Feb':
        month = "02"
    elif month == 'Mar':
        month = "03"
    elif month == 'Apr':
        month = "04"
    elif month == 'May':
        month = "05"
    elif month == 'Jun':
        month = "06"
    elif month == 'Jul':
        month = "07"
    elif month == 'Aug':
        month = "08"
    elif month == 'Sep':
        month = "09"
    elif month == 'Oct':
        month = "10"
    elif month == 'Nov':
        month = "11"
    elif month == 'Dec':
        month = "12"
    
    return year+"-"+month


# In[83]:


def gen_section(mypath):
    pe = pefile.PE(mypath)
   # print(pe.sections[0])
    en = False
    eop = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    sec = {}
    sec['sections'] = []
    '''
    for section in pe.sections:
        print(section.Name, section.Misc, section.Misc_PhysicalAddress,
              section.Misc_VirtualSize, section.VirtualAddress, section.SizeOfRawData,
              section.PointerToRawData, section.PointerToRelocations, section.PointerToLinenumbers,
              section.NumberOfRelocations, section.NumberOfLinenumbers, section.Characteristics)
    '''
    for section in pe.sections:
        arr = [section.Misc, section.Misc_PhysicalAddress,
              section.Misc_VirtualSize, section.VirtualAddress, section.SizeOfRawData,
              section.PointerToRawData, section.PointerToRelocations, section.PointerToLinenumbers,
              section.NumberOfRelocations, section.NumberOfLinenumbers, section.Characteristics]
        #print(arr)
        tmp = {}
        tmp['name'] = (section.Name).decode('utf-8')[:5]
        tmp['vsize'] = section.Misc_VirtualSize
        tmp['size'] = section.SizeOfRawData
        tmp['entropy'] = Entropy(arr)
        sec['sections'].append(tmp)
        
    
    for section in pe.sections:
        if section.contains_rva(eop):
            sec['entry'] = section
            en = True
    if not en:
        sec['entry'] = None
    return sec


# In[ ]:


["Names","Misc","Misc_PhysicalAddress","Misc_VirtualSize",VirtualAddress,SizeOfRawData,PointerToRawData,
 PointerToRelocations,PointerToLinenumbers,NumberOfRelocations,NumberOfLinenumbers,Characteristics]


# In[76]:


def gen_total(mypath):    
    total = {}

    total['general'] = gen_general(mypath)
    total['strings'] = gen_strings(mypath)
    total['histogram'] = gen_hist(mypath)
    total['imports'], total['exports'] = gen_ie(mypath)
    total['sha256'] = gen_sha256(mypath)
    total['appeared'] = gen_appeared(mypath)
    total['section'] = gen_section(mypath)
    return total


# In[79]:


if __name__ == '__main__':
    json_save = []
    argc = len(sys.argv)
    df = True
    for i in range(1, argc):
        if isdir(sys.argv[i]):
            df = False
        
    if df:
        for i in range(1,argc):
            mypath = sys.argv[1]
            tmp = gen_total(mypath)
            json_save.append(tmp)
            with jsonlines.open('output.jsonl', mode='w') as writer:
                writer.write(json_save)
    elif (not df):
        files = listdir(fpath)
        for f in files:
            mypath = fpath + '/' + f
            tmp = gen_total(mypath)
            json_save.append(tmp)
        with jsonlines.open('output.jsonl', mode='w') as writer:
            writer.write(json_save)
    else:
        print("\nPlease enter files' name seperated by space or a direction name ! \n")



