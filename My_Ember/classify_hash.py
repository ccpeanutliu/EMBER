#!/usr/bin/env python
# coding: utf-8

#!/usr/bin/env python
# coding: utf-8

# In[43]:


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
from keras.models import load_model
import yara

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
    general = arr[0]
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
        print('OMG, NO IMPORT TABLE QQ!!!')

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

def gen_num(total):
    n = len(total)
    output = []
    for obj in range(n):
        feature_num = []
        for i in range(3):
            feature_num.append([])
        for j in keys_strings:
            if j != 'printabledist':
                feature_num[0].append(total[obj]['strings'][j])
            else:
                for k in range(96):
                    feature_num[0].append(total[obj]['strings'][j][k])
        for i in range(256):
            feature_num[1].append(total[obj]['histogram'][i])
        for i in keys_general:
            feature_num[2].append(total[obj]['general'][i])
        for i in range(256 - 104):
            feature_num[0].append(0)
        for i in range(256 - 10):
            feature_num[2].append(0)
        output.append(feature_num)
    output = np.array(output)
    return output

def gen_stoi(total):
    output = []
    n = len(total)
    for i in range(n):
        htable = np.zeros(256)
        rnn = [[]]
        try:
            for objs in total[i]['imports']:
                for obj in total[i]['import'][objs]:
                    rnn[0].append(obj)
        except:
            for j in range(256):
                rnn[0].append(0)
        try:
            for objs in total[i]['exports']:
                for obj in total[i]['exports'][objs]:
                    rnn[0].append(obj)
        except:
            continue
        for obj in rnn[0]:
            num = hash(obj) % 256
            htable[num] += 1
        output.append(htable)
    output = np.array(output)
    return output
        
def gen_yara(rule_path, fpath):
    rules = yara.compile(rule_path)
    with open(fpath, 'rb') as f:
        matches = rules.match(data=f.read())
    return matches
    
# In[57]:


if __name__ == '__main__':
    keys_strings = ['avlength', 'numstrings', 'registry', 'urls', 'MZ', 'printables', 'entropy', 'paths', 'printabledist']
    keys_general = ['exports', 'has_resources', 'imports', 'symbols', 'has_signature', 'has_relocations', 'has_debug', 'vsize', 'size', 'has_tls']
    json_save = []
    yara_save = []
    argc = len(sys.argv)
    df = True
    for i in range(1, argc):
        if isdir(sys.argv[i]):
            df = False
    name = []
    if df:
        for i in range(1,argc):
            mypath = sys.argv[i]
            tmp = gen_total(mypath)
            json_save.append(tmp)
            yara_save.append(gen_yara("./yargen_rules.yar",mypath))
            name.append(mypath)
        
    elif (not df) and argc == 2:
        fpath = sys.argv[1]
        files = listdir(fpath)
        for f in files:
            mypath = fpath + '/' + f
            print(f)
            tmp = gen_total(mypath)
            json_save.append(tmp)
            yara_save.append(gen_yara("./yargen_rules.yar",mypath))
            name.append(f)

    else:
        sys.exit("\nPlease enter files' name seperated by space or a direction name ! \n")
    
    o1 = gen_num(json_save)
    o2 = gen_stoi(json_save)
    on = o2.shape[0]
    o2 = o2.reshape(on,1,256)
    print(o1.shape,o2.shape)
    use = np.hstack((o1,o2))
    model = load_model("/home/imccpeanut/Ember_Test/My_Ember/Feature_hash.h5")
    np.random.seed(1230)
    prediction = model.predict(use)
    n = len(prediction)
    
    print("\n# # # # The Result ( Dangerous score 0 ~ 1) # # # #\n")
    for i in range(n):
        print(name[i],"\t" ,prediction[i][0])
    for i in range(n):
        if prediction[i][0] < 0.5 and yara_save[i] != []:
            print("\nThough it seems that "+ name[i] +" isn't dangerous, but it hits some yara rule!!!\n")
            for j in yara_save[i]:
                print(j)