/*
MD5 hash collision and exploitation.

MD5 works with blocks of 64 bytes.
If two contents A & B have the same hash, then appending the same contents C to both will keep the same hash.

hash(A) = hash(B) -> hash(A + C) = hash(B + C)

Exploiting this simple priciple, is possible to get two different files with the same MD5.
There are several attacks to generate MD5 collision, here we are interested in attacks for file
having identical prefixes.

This attack is composed of the following steps:
    1. Define an arbitrary prefix - its content and length don't matter.
    2. Pad the prefix to the next 64-byte block.
    3. Compute collision block(s) based on the prefix and append them to the prefix. 
       Both sides are very random. The differences are predetermined by the attack.
    4. Get two different files, by concatenating the prefix with each of the two blocks: 
       the hash is the same for the two file despite the differences.
    5. Add any arbitrary identical suffix: the hash will remain the same for the two files.

+----------------+---+-----------------+
|    GOOD FILE   |   |    EVIL FILE    |
+----------------+---+-----------------+
| Prefix         | = | Prefix          |
| [n * 64 bytes] |   | [n * 64 bytes]  |
|----------------|---|-----------------|
| Collision A    | ≠ | Collision B     |
| [128 bytes]    |   | [128 bytes]     |
|----------------|---|-----------------|
| Suffix         | = | Suffix          |
| [any length]   |   | [any length]    |
+----------------+---+-----------------+

In the end, the files are almost identical, except a few bits of differences.

For the exploitation, we use an approach called data exploit: run code that 
looks for differences and displays one content or the other (typically trivial since differences are known in advance).

In particular, we use [FastColl](https://www.win.tue.nl/hashclash/) to generate the two collision blocks, given the prefix.
Each collision block needs two MDS blocks (so it is 128 bytes long). This is the difference mask for the two collision blocks:

................
...X............
.............XX.
...........X....
................
...X............
.............XX.
...........X....

Looking at the difference mask, the 20th byte is the first byte that shows a difference (each . represent one byte).
So, we can use this information to trigger a different behaviour in the two files. Knowing the expected value of the 20th
byte in the collision block, we can create an if based on this value.

Look at the following example showing two collision blocks (courtesy of https://github.com/corkami/collisions):

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

In the first collision block the value of the 20th byte is 0x39, while in the second 0xB9. 
We can exploit this difference writing something like this:

if collision_block[20] = 0x39 then:
    do a good thing
else:
    gdo a bad thing

This is the idea used in the code to create the two source files with same MD5 hash, but different behaviour.
    
References:
[1] https://natmchugh.blogspot.com/2014/10/how-i-made-two-php-files-with-same-md5.html?m=1
[2] https://github.com/corkami/collisions
*/

#include <stdio.h>

// The number of bytes for the prefix and for the collision block
// must be 64 and 128 respectively to generate an MD5 collision
#define N_PREFIX_BYTES 64
#define N_COLLISION_BYTES 128

#define BYTE_TYPE unsigned char

void write_binary_file(
    char *filepath, 
    BYTE_TYPE *prefix,
    BYTE_TYPE *collision,
    BYTE_TYPE *suffix,
    size_t prefix_nbytes, size_t collision_nbytes, size_t suffix_nbytes
){
    FILE *ptr;
     
    ptr = fopen(filepath, "wb");
    fwrite(prefix, sizeof(BYTE_TYPE), prefix_nbytes, ptr);
    fwrite(collision, sizeof(BYTE_TYPE), collision_nbytes, ptr);
    fwrite(suffix, sizeof(BYTE_TYPE), suffix_nbytes, ptr);
    fclose (ptr);
}

int main(){
    size_t n_suffix_bytes;
    char *code_filepaths[2] = {"good.py", "evil.py"};
    unsigned long tot_len=0, curr_len=0;

    // Here the initial and final part of the output code;
    // mind that the prefix must have a length of 64 bytes.
    // The idea here is to take advantage of the slightly 
    // difference between the two collission blocks to generate
    // different outputs in the two programs.
    BYTE_TYPE source_code_prefix[N_PREFIX_BYTES] = "# coding: L1\nprint('%s World!'%('Hello','Goodbye Cruel')['Z'>\"\"\"";
    // As you can see, the output code is in Python language.
    //
    // The different output string is created choosing its initial part 
    // between the elements of a tuple two strings ('Hello','Goodbye Cruel').
    // In particular, the index is a condition on the first different character 
    // between the two collision blocks, i.e., the 20th.
    // If this characher is less than 'Z', the condition is True, 
    // (i.e. it is equivalent to 1), so the second element of the 
    // tuple is selected; otherwise the condition 
    // is False (0), so the first element of the tuple is selected
    // To recap, this is the ungolfed sketch of the code:
    //  is_evil = 'Z' > collision_block[19] 
    //  initial_part = ('Hello','Goodbye Cruel')[is_evil]
    //  print('%s World!'%initial_part)
    BYTE_TYPE source_code_suffix[9] = "\"\"\"[19]])";

    // You can put one this two binary blocks between source_code_prefix and source_code_suffix
    // and get the same MD5 hash, even if the two blocks are slightly different
    BYTE_TYPE collision_blocks[2][N_COLLISION_BYTES] = {
        {
            0xfa, 0x7a, 0x9e, 0x18, 0xf9, 0x0a, 0x57, 0x6a, 0x11, 0x6d, 0x45, 0xf2, 0xf7, 0x53, 0xef, 0xe5,
            0x23, 0x6e, 0xee, 0x8f, 0x98, 0xea, 0x2d, 0x15, 0x5a, 0x16, 0x3c, 0x66, 0x69, 0x20, 0x23, 0xfb,
            0xf2, 0xfb, 0xfb, 0xee, 0xf0, 0x8c, 0x09, 0x87, 0x6b, 0x02, 0xd7, 0x54, 0x18, 0x10, 0x2c, 0xad,
            0x71, 0x4b, 0x3d, 0xae, 0x3d, 0x88, 0xc4, 0x86, 0xe4, 0x19, 0x37, 0x76, 0xd2, 0x32, 0xaf, 0x15,
            0x1c, 0xe1, 0x0c, 0x57, 0xfc, 0xa7, 0x9b, 0x1b, 0x28, 0x30, 0xe3, 0xa2, 0x64, 0xde, 0xe5, 0xc5,
            0x41, 0x34, 0x1e, 0x0e, 0xe6, 0xf8, 0x18, 0x2b, 0x74, 0x0b, 0xd0, 0x57, 0x4f, 0x4c, 0x65, 0xc1,
            0xed, 0x2d, 0xc5, 0xe9, 0xf2, 0xe5, 0xab, 0xb7, 0xd9, 0xb5, 0xeb, 0x30, 0x9a, 0x34, 0x7a, 0x67,
            0x71, 0xdf, 0x3f, 0xcd, 0x85, 0x1e, 0x66, 0xff, 0xa6, 0xbc, 0xd4, 0x68, 0xa8, 0xee, 0x08, 0x78
        },
        {
            0xfa, 0x7a, 0x9e, 0x18, 0xf9, 0x0a, 0x57, 0x6a, 0x11, 0x6d, 0x45, 0xf2, 0xf7, 0x53, 0xef, 0xe5,
            0x23, 0x6e, 0xee, 0x0f, 0x98, 0xea, 0x2d, 0x15, 0x5a, 0x16, 0x3c, 0x66, 0x69, 0x20, 0x23, 0xfb,
            0xf2, 0xfb, 0xfb, 0xee, 0xf0, 0x8c, 0x09, 0x87, 0x6b, 0x02, 0xd7, 0x54, 0x18, 0x90, 0x2c, 0xad,
            0x71, 0x4b, 0x3d, 0xae, 0x3d, 0x88, 0xc4, 0x86, 0xe4, 0x19, 0x37, 0xf6, 0xd2, 0x32, 0xaf, 0x15,
            0x1c, 0xe1, 0x0c, 0x57, 0xfc, 0xa7, 0x9b, 0x1b, 0x28, 0x30, 0xe3, 0xa2, 0x64, 0xde, 0xe5, 0xc5,
            0x41, 0x34, 0x1e, 0x8e, 0xe6, 0xf8, 0x18, 0x2b, 0x74, 0x0b, 0xd0, 0x57, 0x4f, 0x4c, 0x65, 0xc1,
            0xed, 0x2d, 0xc5, 0xe9, 0xf2, 0xe5, 0xab, 0xb7, 0xd9, 0xb5, 0xeb, 0x30, 0x9a, 0xb4, 0x79, 0x67,
            0x71, 0xdf, 0x3f, 0xcd, 0x85, 0x1e, 0x66, 0xff, 0xa6, 0xbc, 0xd4, 0xe8, 0xa8, 0xee, 0x08, 0x78
        }
    };

    // The number of bytes in the suffix can vary, depending on 
    // the code needed to make the source file meaningful
    n_suffix_bytes=sizeof(source_code_suffix) / sizeof(BYTE_TYPE);

    // Write good and evil files. The only thing different is the collision block
    tot_len=0;
    for(int i=0; i<2; ++i){
        write_binary_file(
            code_filepaths[i],
            source_code_prefix, collision_blocks[i], source_code_suffix, 
            N_PREFIX_BYTES, N_COLLISION_BYTES, n_suffix_bytes
        );

        curr_len = N_PREFIX_BYTES + N_COLLISION_BYTES + n_suffix_bytes;
        tot_len += curr_len; 

        printf("\nBytes in %s: %lu", code_filepaths[i], curr_len);
    }
    printf("\nTotal length: %lu\n", tot_len);

    return(0);
}
