#include <stdio.h>

void write_file(
    char *filepath, 
    unsigned char *prefix,
    unsigned char *vec1, unsigned char *vec2,
    unsigned char *file_end,
    int prefix_nbytes, int vec1_nbytes, int vec2_nbytes, int end_nbytes
){
    FILE *ptr;

    unsigned char equal_rel[] = "\"\"\" == \"\"\"";
     
    ptr = fopen(filepath,"wb");
    fwrite(prefix, sizeof(unsigned char), prefix_nbytes, ptr);
    fwrite(vec1, sizeof(unsigned char), vec1_nbytes, ptr);
    fwrite(equal_rel, sizeof(unsigned char), 10, ptr);
    fwrite(vec2, sizeof(unsigned char), vec2_nbytes, ptr);
    fwrite(file_end, sizeof(unsigned char), end_nbytes, ptr);
    fclose (ptr);
}

int main(){
    char good_out_filepath[] = "good.py";
    char evil_out_filepath[] = "evil.py";

    unsigned char template_init[64] = "# coding: latin-1\na='aaaaa';print('Goodbye Cruel World!') if \"\"\"";
    unsigned char template_end[30] = "\"\"\" else print('Hello World!')";

    unsigned char vec1[128] = {
        0x08, 0xca, 0x10, 0xb5, 0xdc, 0xb6, 0x16, 0xc3, 0x0d, 0x30, 0x03, 0x99, 0xb4, 0xab, 0xb3, 0xd2,
        0xa7, 0x9c, 0x9f, 0x39, 0x01, 0xaa, 0xc8, 0x75, 0x0c, 0x36, 0x7f, 0x7e, 0xf5, 0x85, 0xa2, 0x7e,
        0xce, 0xfb, 0xb4, 0xd1, 0x6e, 0x4b, 0x61, 0xf9, 0xcf, 0x69, 0x4a, 0x1a, 0xb3, 0xd1, 0xaf, 0x1f,
        0xd4, 0xf1, 0x76, 0x81, 0xb7, 0xc3, 0x36, 0x61, 0xe2, 0x3c, 0x6a, 0x90, 0xe2, 0xe7, 0xa5, 0x34,
        0x18, 0x0c, 0x6d, 0x8c, 0x7e, 0xd1, 0x89, 0xf6, 0xef, 0x44, 0x8d, 0xdb, 0x0d, 0x68, 0xf0, 0xa6,
        0x4d, 0x52, 0x86, 0x27, 0xee, 0x27, 0x6b, 0x0e, 0x74, 0x7b, 0xdb, 0xdb, 0x4f, 0x0d, 0xc3, 0x41,
        0x99, 0xf6, 0xb4, 0x8a, 0xf5, 0x4f, 0xa3, 0x5f, 0x2b, 0x9d, 0x67, 0x99, 0xf4, 0x0f, 0xf5, 0xe4,
        0x14, 0xa4, 0x36, 0x98, 0x82, 0xb9, 0xa6, 0x17, 0x52, 0xfb, 0xe8, 0x0a, 0x75, 0x4f, 0xe6, 0x01
    };

    unsigned char vec2[128] = {
        0x08, 0xca, 0x10, 0xb5, 0xdc, 0xb6, 0x16, 0xc3, 0x0d, 0x30, 0x03, 0x99, 0xb4, 0xab, 0xb3, 0xd2,
        0xa7, 0x9c, 0x9f, 0xb9, 0x01, 0xaa, 0xc8, 0x75, 0x0c, 0x36, 0x7f, 0x7e, 0xf5, 0x85, 0xa2, 0x7e,
        0xce, 0xfb, 0xb4, 0xd1, 0x6e, 0x4b, 0x61, 0xf9, 0xcf, 0x69, 0x4a, 0x1a, 0xb3, 0x51, 0xb0, 0x1f,
        0xd4, 0xf1, 0x76, 0x81, 0xb7, 0xc3, 0x36, 0x61, 0xe2, 0x3c, 0x6a, 0x10, 0xe2, 0xe7, 0xa5, 0x34,
        0x18, 0x0c, 0x6d, 0x8c, 0x7e, 0xd1, 0x89, 0xf6, 0xef, 0x44, 0x8d, 0xdb, 0x0d, 0x68, 0xf0, 0xa6,
        0x4d, 0x52, 0x86, 0xa7, 0xee, 0x27, 0x6b, 0x0e, 0x74, 0x7b, 0xdb, 0xdb, 0x4f, 0x0d, 0xc3, 0x41,
        0x99, 0xf6, 0xb4, 0x8a, 0xf5, 0x4f, 0xa3, 0x5f, 0x2b, 0x9d, 0x67, 0x99, 0xf4, 0x8f, 0xf4, 0xe4,
        0x14, 0xa4, 0x36, 0x98, 0x82, 0xb9, 0xa6, 0x17, 0x52, 0xfb, 0xe8, 0x8a, 0x75, 0x4f, 0xe6, 0x01
    };
    int vec1_nbytes = 128, vec2_nbytes = 128, template_init_nbytes=64, template_end_nbytes=30;

    // write good file
    write_file(
        good_out_filepath, template_init, vec1, vec2, template_end, 
        template_init_nbytes, vec1_nbytes, vec2_nbytes, template_end_nbytes
    );

    // write bad file
    write_file(
        evil_out_filepath, template_init, vec2, vec2, template_end, 
        template_init_nbytes, vec1_nbytes, vec1_nbytes, template_end_nbytes
    );

    return(0);
}
