#define _GNU_SOURCE
#include <openssl/md5.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _OPENMP
#include <omp.h>
#endif

/* RSA-100 known-factor pre-prime intervals after RSAREF range reduction. */
static const unsigned char lo1[21] = {0x01,0xfb,0xd4,0x1d,0x69,0xaa,0x3d,0x86,0x00,0x9a,0x96,0x7d,0xb3,0x37,0x9c,0x63,0xcd,0x50,0x1f,0x24,0xe5};
static const unsigned char hi1[21] = {0x01,0xfb,0xd4,0x1d,0x69,0xaa,0x3d,0x86,0x00,0x9a,0x96,0x7d,0xb3,0x37,0x9c,0x63,0xcd,0x50,0x1f,0x24,0xf7};
static const unsigned char lo2[21] = {0x03,0x6f,0x14,0x1f,0x98,0xee,0xb6,0x19,0xbc,0x03,0x60,0x22,0x01,0x60,0xa5,0xf7,0x5e,0xa0,0x7c,0xde,0xc3};
static const unsigned char hi2[21] = {0x03,0x6f,0x14,0x1f,0x98,0xee,0xb6,0x19,0xbc,0x03,0x60,0x22,0x01,0x60,0xa5,0xf7,0x5e,0xa0,0x7c,0xdf,0x1d};

static int in_range(const unsigned char *x, const unsigned char *lo, const unsigned char *hi) {
    return memcmp(x, lo, 21) > 0 && memcmp(x, hi, 21) <= 0;
}
static void add128(unsigned char state[16], const unsigned char x[16]) {
    unsigned carry = 0;
    for (int i = 15; i >= 0; --i) {
        unsigned v = (unsigned)state[i] + x[i] + carry;
        state[i] = (unsigned char)v;
        carry = v >> 8;
    }
}
static void mul_small128(unsigned char state[16], unsigned m) {
    unsigned carry = 0;
    for (int i = 15; i >= 0; --i) {
        unsigned v = (unsigned)state[i] * m + carry;
        state[i] = (unsigned char)v;
        carry = v >> 8;
    }
}
static void inc128(unsigned char state[16]) {
    for (int i = 15; i >= 0; --i) if (++state[i]) break;
}
static void put32be(unsigned char *p, uint32_t x) {
    p[0]=(unsigned char)(x>>24); p[1]=(unsigned char)(x>>16); p[2]=(unsigned char)(x>>8); p[3]=(unsigned char)x;
}
static void put32le(unsigned char *p, uint32_t x) {
    p[0]=(unsigned char)x; p[1]=(unsigned char)(x>>8); p[2]=(unsigned char)(x>>16); p[3]=(unsigned char)(x>>24);
}
static unsigned char BYTE_MD5[256][16];
static uint32_t BYTE_MD5W[256][4];
static void md5buf(const void *p, size_t n, unsigned char out[16]) {
    MD5((const unsigned char*)p, n, out);
}
static void init_byte_md5(void) {
    for (int i = 0; i < 256; ++i) {
        unsigned char b = (unsigned char)i;
        md5buf(&b, 1, BYTE_MD5[i]);
        for (int j=0; j<4; ++j) {
            const unsigned char *q = BYTE_MD5[i] + 4*j;
            BYTE_MD5W[i][j] = ((uint32_t)q[0]<<24)|((uint32_t)q[1]<<16)|((uint32_t)q[2]<<8)|q[3];
        }
    }
}
static void add_byte_digests_fast(unsigned char state[16], const unsigned char block[256]) {
    uint32_t w[4] = {0,0,0,0};
    for (int i = 0; i < 256; ++i) {
        const uint32_t *d = BYTE_MD5W[block[i]];
        uint64_t z = (uint64_t)w[3] + d[3]; w[3]=(uint32_t)z; uint64_t c=z>>32;
        z = (uint64_t)w[2] + d[2] + c; w[2]=(uint32_t)z; c=z>>32;
        z = (uint64_t)w[1] + d[1] + c; w[1]=(uint32_t)z; c=z>>32;
        z = (uint64_t)w[0] + d[0] + c; w[0]=(uint32_t)z;
    }
    for (int j=0; j<4; ++j) put32be(state+4*j,w[j]);
}

static void init_state(uint32_t t, int mode, unsigned char state[16]) {
    unsigned char b4[4], block[256], d[16];
    memset(state,0,16); memset(block,0,sizeof(block));
    switch(mode) {
    case 0: put32be(state+12,t); break;
    case 1: put32le(state+12,t); break;
    case 2: put32be(state,t); break;
    case 3: put32le(state,t); break;
    case 4: for(int i=0;i<4;i++) put32be(state+4*i,t); break;
    case 5: for(int i=0;i<4;i++) put32le(state+4*i,t); break;
    case 10: put32be(b4,t); md5buf(b4,4,state); break;
    case 11: put32le(b4,t); md5buf(b4,4,state); break;
    case 12: put32be(b4,t); md5buf(b4,4,state); mul_small128(state,64); break;
    case 13: put32le(b4,t); md5buf(b4,4,state); mul_small128(state,64); break;
    case 14: for(int i=0;i<64;i++) put32be(block+4*i,t); md5buf(block,256,state); break;
    case 15: for(int i=0;i<64;i++) put32le(block+4*i,t); md5buf(block,256,state); break;
    case 16: put32be(block,t); md5buf(block,256,state); break;
    case 17: put32le(block,t); md5buf(block,256,state); break;
    case 18: put32be(block+252,t); md5buf(block,256,state); break;
    case 19: put32le(block+252,t); md5buf(block,256,state); break;
    case 20:
    case 21: {
        if(mode==20) put32be(b4,t); else put32le(b4,t);
        for(int j=0;j<4;j++) { md5buf(&b4[j],1,d); mul_small128(d,64); add128(state,d); }
        break;
    }
    case 22: {
        char s[32]; int n=snprintf(s,sizeof(s),"%u",t); md5buf(s,(size_t)n,state); break;
    }
    case 23: {
        char s[32]; int n=snprintf(s,sizeof(s),"%u",t); for(int i=0;i<256;i++) block[i]=(unsigned char)s[i%n]; md5buf(block,256,state); break;
    }
    case 24: {
        char s[32]; int n=snprintf(s,sizeof(s),"%u",t); md5buf(s,(size_t)n,state); mul_small128(state,64); break;
    }
    case 30: case 31: case 32: case 33:
    case 34: case 35: case 36: case 37:
    case 38: case 39: case 40: case 41:
    case 42: case 43:
    case 50: case 51: case 52: case 53:
    case 54: case 55: case 56: case 57:
    case 58: case 59: case 60: case 61:
    case 62: case 63: {
        int per_byte = (mode >= 50);
        int base_mode = per_byte ? mode - 20 : mode;
        uint32_t x=t, A=0, C=0; int style=base_mode%4;
        if(base_mode>=30 && base_mode<=33){ A=214013u; C=2531011u; }
        else if(base_mode>=34 && base_mode<=37){ A=1103515245u; C=12345u; }
        else if(base_mode>=38 && base_mode<=41){ A=22695477u; C=1u; }
        else { A=1664525u; C=1013904223u; style=(base_mode==42?0:1); }
        int pos=0;
        while(pos<256){
            x=A*x+C;
            uint32_t r=(base_mode>=42)?x:((x>>16)&0x7fffu);
            if(style==0) block[pos++]=(unsigned char)r;
            else if(style==1) block[pos++]=(unsigned char)((base_mode>=42)?(r>>24):(r>>7));
            else if(style==2){ block[pos++]=(unsigned char)r; if(pos<256) block[pos++]=(unsigned char)(r>>8); }
            else { block[pos++]=(unsigned char)(r>>8); if(pos<256) block[pos++]=(unsigned char)r; }
        }
        if (per_byte) add_byte_digests_fast(state, block); else md5buf(block,256,state);
        break;
    }
    default: fprintf(stderr,"unknown mode %d\n",mode); exit(2);
    }
}

static int scan_one(uint32_t t, int mode, int ncalls, int *which, int *callidx) {
    unsigned char state[16], stream[16*64], dig[16], r[21];
    init_state(t,mode,state);
    int nbytes=24*ncalls, nd=(nbytes+15)/16;
    for(int j=0;j<nd;j++) { md5buf(state,16,dig); memcpy(stream+16*j,dig,16); inc128(state); }
    for(int i=0;i<ncalls;i++) {
        const unsigned char *raw=stream+24*i;
        memcpy(r,raw+3,21); r[0]&=0x07; r[20]|=1;
        if(in_range(r,lo1,hi1)) { *which=1; *callidx=i; return 1; }
        if(in_range(r,lo2,hi2)) { *which=2; *callidx=i; return 1; }
    }
    return 0;
}

int main(int argc,char **argv) {
    init_byte_md5();
    if(argc<6){fprintf(stderr,"usage: %s start end mode ncalls threads\n",argv[0]);return 2;}
    uint64_t start=strtoull(argv[1],0,0), end=strtoull(argv[2],0,0);
    int mode=atoi(argv[3]), ncalls=atoi(argv[4]), nth=atoi(argv[5]);
#ifdef _OPENMP
    omp_set_num_threads(nth);
#endif
    double t0=
#ifdef _OPENMP
      omp_get_wtime();
#else
      0.0;
#endif
    volatile int found=0;
    uint64_t hit_t=0; int hit_w=0,hit_i=0;
#pragma omp parallel for schedule(static)
    for(uint64_t x=start;x<end;x++) {
        if(found) continue;
        int w=0,i=0;
        if(scan_one((uint32_t)x,mode,ncalls,&w,&i)) {
#pragma omp critical
            { if(!found){found=1;hit_t=x;hit_w=w;hit_i=i;} }
        }
    }
    double t1=
#ifdef _OPENMP
      omp_get_wtime();
#else
      1.0;
#endif
    printf("mode=%d start=%llu end=%llu ncalls=%d threads=%d elapsed=%.3f rate=%.0f/s found=%d",
      mode,(unsigned long long)start,(unsigned long long)end,ncalls,nth,t1-t0,(end-start)/(t1-t0),found);
    if(found) printf(" seed=%llu which=%d call=%d",(unsigned long long)hit_t,hit_w,hit_i);
    printf("\n");
    return found?0:1;
}
