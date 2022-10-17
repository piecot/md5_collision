# MD5 Collision
A little project to investigate md5 collision.

In particular, this is the support code for the answer to [this question](https://codegolf.stackexchange.com/q/253296/49690) on Codegolf.
The question asked for two programs with the same MD5 of their source codes but different outputs.

The code in this repo is inspired to [this blog post](https://natmchugh.blogspot.com/2014/10/how-i-made-two-php-files-with-same-md5.html?m=1) by Nat McHugh.

The content of the repo is:
- two Python scripts with the same MD5 hash, but different outputs: [good.py](good.py) and [evil.py](evil.py)
- a C code ([create_evil_good_bin.c](create_evil_good_bin.c)) to generate the two Python scripts. The file can be compiled running:
```bash
gcc -o create_source_files create_evil_good_bin.c
```
Then, the two Python files can be generated running:
```bash
./create_source_files
```