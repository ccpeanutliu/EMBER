# EMBER
My research of EMBER dataset

### EMBER的資料生成程式已完成，在My_Ember資料夾中，使用方法:

```
python3 ember_jsonl.py b/m/n ./dir
```
或
```
python3 ember_jsonl.py b/m/n ./file1 ./file2 ...
```
Required Model_Ember, numpy, pefile, re, matplotlib, pandas, scipy, lief

其中 b 代表benign、m 代表malware、n 代表沒有label(for no supervised training)

##### 注意，所生成的output.jsonl檔案中是一個array裡面包著許多的dictionary，與EMBER直接存成很多dictionary有一點不同(我也不知道他是怎麼不用array包起來就能存的)

### EMBER可以用了！請使用My_Ember資料夾中classify_hash.py，使用方法:
```
python3 classify_hash.py ./dir
```
或
```
python3 classify_hash.py ./file1 ./file2 ...
```
Required Model_Ember, numpy, pefile, re, matplotlib, keras

2019/8/14 Update：加入了yara rule，新增了classify_hash.py、yargen_rules.py

### 不要用classify.py，那個是錯的。
