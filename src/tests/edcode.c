#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

char encode_c(int x) {
    x = x & 63;
    if (x < 10) 
        return x + '0';
    else if (x < 10 + 26)
        return x - 10 + 'a';
    else if (x < 10 + 26 + 26)
        return x - 10 - 26 + 'A';
    else if (x == 62) return '/';
    else return '=';
}

int decode_c(char c){
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'Z')
        return c - 'A' + 10 + 26;
    if (c == '/')
        return 62;
    if (c == '=')
        return 63;
}

char buf_s[684];
char buf_c[684];

void encode(bool* x, char* buf){
    int k = 0;
    for (int i = 0, j = 0, y = 0; i < 4096; i++) {
        y = (y << 1) | x[i];
        if (i == 4095 || j == 5) {
            j = 0;
            if (i == 4095)
                y <<= 2;
            buf[k++] = encode_c(y);
        } else j++;
    }
    buf[k] = 0;
}
void decode(bool* x, char* buf){
    for (int i = 0, j = -1, k = 0, y = 0; i < 4096; i++) {
        if (j == -1) {
            j = 5;
            y = decode_c(buf[k++]);
        }
        x[i] = (y >> j)&1;
        j--;
    }
}

bool ans[4096], snd[4096];

int main(){
    for (int i = 0; i < 64; i++) {
        if (decode_c(encode_c(i)) != i)
            printf("failed %d %d %c\n", i, decode_c(encode_c(i)), encode_c(i));
    }

    for (int T = 0; T < 100000; T++) {
        for (int i = 0; i < 4096; i++)
            snd[i]  =rand()%2;
        encode(snd, buf_s);
        if (T<=10)
            printf("%s\n", buf_s);
        decode(ans, buf_s);
        for (int i = 0; i < 4096; i++)
            if (snd[i] != ans[i]) {
                puts("Incorrect!!!");
                printf("%d\n", i);
                return 0;
            }
    }
    puts("Succ!!!");
}