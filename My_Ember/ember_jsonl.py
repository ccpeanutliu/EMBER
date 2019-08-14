#!/usr/bin/env python
# coding: utf-8

# In[18]:


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
import lief
from scipy import stats
import pandas as pd

def Entropy(labels, base=2):
    # 计算概率分布
    probs = pd.Series(labels).value_counts() / len(labels)
    # 计算底数为base的熵
    en = stats.entropy(probs, base=base)
    return en


# In[20]:


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


# In[56]:


def gen_general(mypath):   
    lief_binary = lief.parse(mypath)
    bytez = bytearray(open(mypath, 'rb').read())
            
    if lief_binary is None:
        return {
            'size': len(bytez),
            'vsize': 0,
            'has_debug': 0,
            'exports': 0,
            'imports': 0,
            'has_relocations': 0,
            'has_resources': 0,
            'has_signature': 0,
            'has_tls': 0,
            'symbols': 0
        }
    return{
        'size': len(bytez),
        'vsize': lief_binary.virtual_size,
        'has_debug': int(lief_binary.has_debug),
        'exports': len(lief_binary.exported_functions),
        'imports': len(lief_binary.imported_functions),
        'has_relocations': int(lief_binary.has_relocations),
        'has_resources': int(lief_binary.has_resources),
        'has_signature': int(lief_binary.has_signature),
        'has_tls': int(lief_binary.has_tls),
        'symbols': len(lief_binary.symbols),
    }



def gen_strings(mypath):
    npsl = []
    for qq in range(1):
        fullpath = mypath
        sl = list(strings(fullpath))
        npsl.append(sl)
    test = len(npsl[0])
    allstrings = []
    for i in range(test):
        allstrings.append(str.encode(npsl[0][i]))
    if allstrings:
        # statistics about strings:
        string_lengths = [len(s) for s in allstrings]
        avlength = sum(string_lengths) / len(string_lengths)
        # map printable characters 0x20 - 0x7f to an int array consisting of 0-95, inclusive
        as_shifted_string = [np.abs(b - ord(b'\x20')) for b in b''.join(allstrings)]
        c = np.bincount(as_shifted_string, minlength=96)  # histogram count
        # distribution of characters in printable strings
        csum = c.sum()
        p = c.astype(np.float32) / csum
        wh = np.where(c)[0]
        H = np.sum(-p[wh] * np.log2(p[wh]))  # entropy
    else:
        avlength = 0
        c = np.zeros((96,), dtype=np.float32)
        H = 0
        csum = 0
    
    num = 0
    MZ = 0
    for obj in npsl[num]:
        if 'MZ' in obj:
            MZ += 1
    urls = 0
    for obj in npsl[num]:
        if 'https://' in obj or 'http://' in obj:
            urls += 1
    registry = 0
    for obj in npsl[num]:
        if 'HKEY_ ' in obj:
            registry += 1
            print(obj)
    paths = 0
    for obj in npsl[num]:
        if 'C:\\' == obj[0:3] or 'D:\\' == obj[0:3]:
            paths += 1
            
    
    return {
        'numstrings': len(allstrings),
        'avlength': avlength,
        'printabledist': c.tolist(),  # store non-normalized histogram
        'printables': int(csum),
        'entropy': float(H),
        'paths': paths,
        'urls': urls,
        'registry': registry,
        'MZ': MZ
    }
    return allstrings


# # Histogram

# In[54]:


def gen_hist(mypath):    
    bytez = bytearray(open(mypath, 'rb').read())
    counts = np.bincount(np.frombuffer(bytez, dtype=np.uint8), minlength=256)
    return counts.tolist()


# In[64]:


def gen_byteentropy(mypath):
    lief_binary = lief.parse(mypath)    
    bytez = bytearray(open(mypath, 'rb').read())
    name = 'byteentropy'
    dim = 256
    window = 2048
    step = 1024
    def _entropy_bin_counts(block):
        # coarse histogram, 16 bytes per bin
        c = np.bincount(block >> 4, minlength=16)  # 16-bin histogram
        p = c.astype(np.float32) / window
        wh = np.where(c)[0]
        H = np.sum(-p[wh] * np.log2(
            p[wh])) * 2  # * x2 b.c. we reduced information by half: 256 bins (8 bits) to 16 bins (4 bits)

        Hbin = int(H * 2)  # up to 16 bins (max entropy is 8 bits)
        if Hbin == 16:  # handle entropy = 8.0 bits
            Hbin = 15

        return Hbin, c

    output = np.zeros((16, 16), dtype=np.int)
    a = np.frombuffer(bytez, dtype=np.uint8)
    if a.shape[0] < window:
        Hbin, c = _entropy_bin_counts(a)
        output[Hbin, :] += c
    else:
        # strided trick from here: http://www.rigtorp.se/2011/01/01/rolling-statistics-numpy.html
        shape = a.shape[:-1] + (a.shape[-1] - window + 1, window)
        strides = a.strides + (a.strides[-1],)
        blocks = np.lib.stride_tricks.as_strided(a, shape=shape, strides=strides)[::step, :]

        # from the blocks, compute histogram
        for block in blocks:
            Hbin, c = _entropy_bin_counts(block)
            output[Hbin, :] += c

    return output.flatten().tolist()

# In[24]:


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


# In[25]:


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


# In[26]:


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


# In[78]:


def gen_section(mypath):
    lief_binary = lief.parse(mypath)
    if lief_binary is None:
        return {"entry": "", "sections": []}
    def properties(s):
        return [str(c).split('.')[-1] for c in s.characteristics_lists]
    # properties of entry point, or if invalid, the first executable section
    try:
        entry_section = lief_binary.section_from_offset(lief_binary.entrypoint).name
    except lief.not_found:
        # bad entry point, let's find the first executable section
        entry_section = ""
        for s in lief_binary.sections:
            if lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE in s.characteristics_lists:
                entry_section = s.name
                break

    raw_obj = {"entry": entry_section}
    raw_obj["sections"] = [{
        'name': s.name,
        'size': s.size,
        'entropy': s.entropy,
        'vsize': s.virtual_size,
        'props': properties(s)
    } for s in lief_binary.sections]
    return raw_obj


# In[28]:


def gen_header(mypath):
    lief_binary = lief.parse(mypath)
    raw_obj = {}
    raw_obj['coff'] = {'timestamp': 0, 'machine': "", 'characteristics': []}
    raw_obj['optional'] = {
        'subsystem': "",
        'dll_characteristics': [],
        'magic': "",
        'major_image_version': 0,
        'minor_image_version': 0,
        'major_linker_version': 0,
        'minor_linker_version': 0,
        'major_operating_system_version': 0,
        'minor_operating_system_version': 0,
        'major_subsystem_version': 0,
        'minor_subsystem_version': 0,
        'sizeof_code': 0,
        'sizeof_headers': 0,
        'sizeof_heap_commit': 0
    }
    if lief_binary is None:
        return raw_obj
    raw_obj['coff']['timestamp'] = lief_binary.header.time_date_stamps
    raw_obj['coff']['machine'] = str(lief_binary.header.machine).split('.')[-1]
    raw_obj['coff']['characteristics'] = [str(c).split('.')[-1] for c in lief_binary.header.characteristics_list]
    raw_obj['optional']['subsystem'] = str(lief_binary.optional_header.subsystem).split('.')[-1]
    raw_obj['optional']['dll_characteristics'] = [str(c).split('.')[-1] for c in lief_binary.optional_header.dll_characteristics_lists]
    raw_obj['optional']['magic'] = str(lief_binary.optional_header.magic).split('.')[-1]
    raw_obj['optional']['major_image_version'] = lief_binary.optional_header.major_image_version
    raw_obj['optional']['minor_image_version'] = lief_binary.optional_header.minor_image_version
    raw_obj['optional']['major_linker_version'] = lief_binary.optional_header.major_linker_version
    raw_obj['optional']['minor_linker_version'] = lief_binary.optional_header.minor_linker_version
    raw_obj['optional']['major_operating_system_version'] = lief_binary.optional_header.major_operating_system_version
    raw_obj['optional']['minor_operating_system_version'] = lief_binary.optional_header.minor_operating_system_version
    raw_obj['optional']['major_subsystem_version'] = lief_binary.optional_header.major_subsystem_version
    raw_obj['optional']['minor_subsystem_version'] = lief_binary.optional_header.minor_subsystem_version
    raw_obj['optional']['sizeof_code'] = lief_binary.optional_header.sizeof_code
    raw_obj['optional']['sizeof_headers'] = lief_binary.optional_header.sizeof_headers
    raw_obj['optional']['sizeof_heap_commit'] = lief_binary.optional_header.sizeof_heap_commit
    return raw_obj


# In[75]:


def gen_total(mypath,label):    
    total = {}
    if label == 'B' or label == 'b':
        total['label'] = 0
    elif label == 'M' or label == 'm':
        total['label'] = 1
    elif label == 'N' or label == 'n':
        total['label'] = -1
    else:
        print('Please enter correct label !!!')
    
    total['general'] = gen_general(mypath)
    total['strings'] = gen_strings(mypath)
    total['histogram'] = gen_hist(mypath)
    total['imports'], total['exports'] = gen_ie(mypath)
    total['sha256'] = gen_sha256(mypath)
    total['appeared'] = gen_appeared(mypath)
    total['section'] = gen_section(mypath)
    total['header'] = gen_header(mypath)
    total['byteentropy'] = gen_byteentropy(mypath)
    
    return total


# In[79]:


if __name__ == '__main__':
    label = sys.argv[1]
    json_save = []
    argc = len(sys.argv)
    df = True
    for i in range(2, argc):
        if isdir(sys.argv[i]):
            df = False
        
    if df:
        for i in range(2,argc):
            mypath = sys.argv[i]
            tmp = gen_total(mypath,label)
            json_save.append(tmp)
            with jsonlines.open('output.jsonl', mode='w') as writer:
                writer.write(json_save)
    elif (not df) and argc == 3:
        files = listdir(fpath)
        for f in files:
            mypath = fpath + '/' + f
            tmp = gen_total(mypath,label)
            json_save.append(tmp)
        with jsonlines.open('output.jsonl', mode='w') as writer:
            writer.write(json_save)
    else:
        print("\nPlease first enter B/M/N(benignware or malware or No label) and second enter files' name seperated by space or a direction name ! \n")

