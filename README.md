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

## MD5 hash collision and exploitation.

MD5 works with blocks of 64 bytes.
If two blocks (with a length multiple of 64 bytes) A & B have the same hash, 
then appending the same contents C to both will keep the same hash.

*hash(A) = hash(B) -> hash(A + C) = hash(B + C)*

Exploiting this simple principle is possible to get two different files with the same MD5.

There are several attacks to generate MD5 collision, here we are interested in attacks for files having **identical prefixes**.

These are the steps of the attack:
 1. Define an arbitrary prefix with any content and length.
 2. Pad the prefix to the next 64-byte block.
 3. Compute collision blocks based on the prefix. The differences between the blocks are predetermined by the attack.
 4. Concatenate the prefix with each of the two blocks to get two different sequences: the hash is the same for the two sequences despite the differences.
 5. Add any arbitrary identical suffix to the sequences: the hash will remain the same for the two sequences.

The final structure of the two files will be the following:
|           GOOD FILE        |   |          EVIL FILE         |
|----------------------------|---|----------------------------|
| Prefix<br>[n * 64 bytes]   | = | Prefix <br>[n * 64 bytes]  |
| Collision A<br>[128 bytes] | ≠ | Collision B<br>[128 bytes] |
| Suffix<br>[any length]     | = | Suffix<br>[any length]     |

In the end, the files are almost identical, except for a few bits.

For the exploitation, we use an approach called **data exploit**: run code that 
looks for differences and displays one content or the other (typically trivial since differences are known in advance).

In particular, we use [FastColl](https://www.win.tue.nl/hashclash/) to generate the two collision blocks, given the prefix.
Each collision block needs two MDS blocks (so it is 128 bytes long). This is the difference mask for the two collision blocks:

```bash
................
...X............
.............XX.
...........X....
................
...X............
.............XX.
...........X....
```

Looking at the difference mask, the 20th byte is the first byte that shows a difference (each . represents one byte).
So, we can use this information to trigger a different behavior in the two files. Knowing the expected value of the 20th
byte in the collision block, we can create an if based on this value.

Look at the following example showing two collision blocks (courtesy of https://github.com/corkami/collisions):

```bash
00:  37 75 C1 F1-C4 A7 5A E7-9C E0 DE 7A-5B 10 80 26  7u┴±─ºZτ£α▐z[►Ç&
10:  02 AB D9 39-C9 6C 5F 02-12 C2 7F DA-CD 0D A3 B0  ☻½┘9╔l_☻↕┬⌂┌═♪ú░
20:  8C ED FA F3-E1 A3 FD B4-EF 09 E7 FB-B1 C3 99 1D  îφ·≤ßú²┤∩○τ√▒├Ö↔
30:  CD 91 C8 45-E6 6E FD 3D-C7 BB 61 52-3E F4 E0 38  ═æ╚Eµn²=╟╗aR>⌠α8  \
40:  49 11 85 69-EB CC 17 9C-93 4F 40 EB-33 02 AD 20  I◄àiδ╠↨£ôO@δ3☻¡ 
50:  A4 09 2D FB-15 FA 20 1D-D1 DB 17 CD-DD 29 59 1E  ñ○-√§· ↔╤█↨═▌)Y▲    ................
60:  39 89 9E F6-79 46 9F E6-8B 85 C5 EF-DE 42 4F 46  9ë₧÷yFƒµïà┼∩▐BOF    ...X............
70:  C2 78 75 9D-8B 65 F4 50-EA 21 C5 59-18 62 FF 7B  ┬xu¥ïe⌠PΩ!┼Y↑b {    .............XX.
                                                                          ...........X....
                                                                          ................
00:  37 75 C1 F1-C4 A7 5A E7-9C E0 DE 7A-5B 10 80 26  7u┴±─ºZτ£α▐z[►Ç&    ...X............
10:  02 AB D9 B9-C9 6C 5F 02-12 C2 7F DA-CD 0D A3 B0  ☻½┘╣╔l_☻↕┬⌂┌═♪ú░    .............XX.
20:  8C ED FA F3-E1 A3 FD B4-EF 09 E7 FB-B1 43 9A 1D  îφ·≤ßú²┤∩○τ√▒CÜ↔    ...........X....
30:  CD 91 C8 45-E6 6E FD 3D-C7 BB 61 D2-3E F4 E0 38  ═æ╚Eµn²=╟╗a╥>⌠α8
40:  49 11 85 69-EB CC 17 9C-93 4F 40 EB-33 02 AD 20  I◄àiδ╠↨£ôO@δ3☻¡   /
50:  A4 09 2D 7B-15 FA 20 1D-D1 DB 17 CD-DD 29 59 1E  ñ○-{§· ↔╤█↨═▌)Y▲
60:  39 89 9E F6-79 46 9F E6-8B 85 C5 EF-DE C2 4E 46  9ë₧÷yFƒµïà┼∩▐┬NF
70:  C2 78 75 9D-8B 65 F4 50-EA 21 C5 D9-18 62 FF 7B  ┬xu¥ïe⌠PΩ!┼┘↑b {
```
In the first collision block, the value of the 20th byte is 0x39, while in the second 0xB9. 
We can exploit this difference by writing something like this:

```python
if collision_block[20] = 0x39 then:
    do a good thing
else:
    do a bad thing
```

This is the idea used in the code to create the two source files with the same MD5 hash, but different behavior.
    
## References:
[1] https://natmchugh.blogspot.com/2014/10/how-i-made-two-php-files-with-same-md5.html?m=1

[2] https://github.com/corkami/collisions
