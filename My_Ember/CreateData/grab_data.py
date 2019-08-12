#!/usr/bin/env python
# coding: utf-8

# In[18]:


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
from keras.models import load_model
from gensim.models import Word2Vec
from keras.preprocessing.sequence import pad_sequences
from keras.layers import Embedding


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
mypath = sys.argv[1]

# In[4]:
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


# # Strings

# In[5]:


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
print(MZ)

# avglength

tl = 0
for obj in npsl[num]:
    tl += len(obj)
avlength = tl/len(npsl[num])
print(avlength)

#numstrings

numstrings = len(npsl[num])
print(numstrings)

# urls

urls = 0
for obj in npsl[num]:
    if 'https://' in obj or 'http://' in obj:
        urls += 1
print(urls)

# paths

paths = 0
for obj in npsl[num]:
    if 'C:\\' == obj[0:3] or 'D:\\' == obj[0:3]:
        paths += 1
print(paths)

# printables

printables = 0
for obj in npsl[num]:
    n = len(obj)
    for i in range(n-5):
        if obj[i:(i+5)].isprintable():
            printables += 1
            break
print(printables)


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
print(registry)

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
strs['printabledist'] = (printabledist)
strs['printables'] = printables
strs['registry'] = registry
strs['urls'] = urls


# # Histogram

# In[6]:


content = bytearray(open(mypath, 'rb').read())

freq, bins, patches = plt.hist(content, 256)

histogram = freq




# In[8]:

# # Combine

output = []
keys_strings = ['avlength', 'numstrings', 'registry', 'urls', 'MZ', 'printables', 'entropy', 'paths', 'printabledist']
keys_general = ['exports', 'has_resources', 'imports', 'symbols', 'has_signature', 'has_relocations', 'has_debug', 'vsize', 'size', 'has_tls']
for obj in range(1):
    feature_num = []
    for i in range(3):
        feature_num.append([])
    for j in keys_strings:
        if j != 'printabledist':
            feature_num[0].append(strs[j])
        else:
            for k in range(96):
                feature_num[0].append(strs[j][k])
    for i in range(256):
        feature_num[1].append(histogram[i])
    for i in keys_general:
        feature_num[2].append(general[i])
    for i in range(256 - 104):
        feature_num[0].append(0)
    for i in range(256 - 10):
        feature_num[2].append(0)
    output.append(feature_num)


# In[9]:


output = np.array(output)


# In[11]:


pe = pefile.PE(mypath)
ie = [[]]
try:
    for imp in pe.DIRECTORY_ENTRY_IMPORT:
        for entry in imp.imports:
            ie[0].append((entry.name).decode('ascii'))
except:
    print('no imports table QQ!!!')

try:
    for exp in pe.DIRECTORY_ENTRY_EXPORT:
        for entry in exp.exports:
            ie[0].append((entry.name).decode('ascii'))
except:
    print('no exports table QQ!!!')


# In[19]:


w2v_model = Word2Vec.load('./Ember_Model/large_w2v.model')

embedding_matrix = np.zeros((len(w2v_model.wv.vocab.items()) + 1, w2v_model.vector_size))
word2idx = {}

vocab_list = [(word, w2v_model.wv[word]) for word, _ in w2v_model.wv.vocab.items()]
for i, vocab in enumerate(vocab_list):
    word, vec = vocab
    embedding_matrix[i + 1] = vec
    word2idx[word] = i + 1
'''
embedding_layer = Embedding(input_dim=embedding_matrix.shape[0],
                            output_dim=embedding_matrix.shape[1],
                            mask_zero=True,
                            weights=[embedding_matrix],
                            trainable=True)
'''
def text_to_index(corpus):
    new_corpus = []
    for doc in corpus:
        new_doc = []
        for word in doc:
            try:
                new_doc.append(word2idx[word])
            except:
                new_doc.append(0)
        new_corpus.append(new_doc)
    return np.array(new_corpus)

PADDING_LENGTH = 256
X = text_to_index(ie)
X = pad_sequences(X, maxlen=PADDING_LENGTH)

table = X


# In[22]:


output = output.reshape(3,256)


# In[30]:


total = np.vstack((output,X))
total = total.reshape(1,4,256)


# In[31]:


model = load_model("./Ember_Model/No_Byteentropy.h5")


# In[34]:


prediction = model.predict(total)


# In[37]:


print(sys.argv[1],"\t" ,prediction[0][0])

