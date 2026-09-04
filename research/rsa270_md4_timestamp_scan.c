#define _GNU_SOURCE
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

static inline uint32_t rol(uint32_t x, unsigned n) { return (x << n) | (x >> (32-n)); }
static inline uint32_t rd32le(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
static inline void wr32le(unsigned char *p, uint32_t x) {
    p[0]=(unsigned char)x; p[1]=(unsigned char)(x>>8); p[2]=(unsigned char)(x>>16); p[3]=(unsigned char)(x>>24);
}
static void md4_compress(uint32_t h[4], const unsigned char block[64]) {
    uint32_t x[16],a=h[0],b=h[1],c=h[2],d=h[3];
    for(int i=0;i<16;i++) x[i]=rd32le(block+4*i);
#define F(x,y,z) (((x)&(y))|(~(x)&(z)))
#define G(x,y,z) (((x)&(y))|((x)&(z))|((y)&(z)))
#define H(x,y,z) ((x)^(y)^(z))
#define R1(a,b,c,d,k,s) a=rol(a+F(b,c,d)+x[k],s)
#define R2(a,b,c,d,k,s) a=rol(a+G(b,c,d)+x[k]+0x5a827999u,s)
#define R3(a,b,c,d,k,s) a=rol(a+H(b,c,d)+x[k]+0x6ed9eba1u,s)
    R1(a,b,c,d,0,3); R1(d,a,b,c,1,7); R1(c,d,a,b,2,11); R1(b,c,d,a,3,19);
    R1(a,b,c,d,4,3); R1(d,a,b,c,5,7); R1(c,d,a,b,6,11); R1(b,c,d,a,7,19);
    R1(a,b,c,d,8,3); R1(d,a,b,c,9,7); R1(c,d,a,b,10,11); R1(b,c,d,a,11,19);
    R1(a,b,c,d,12,3); R1(d,a,b,c,13,7); R1(c,d,a,b,14,11); R1(b,c,d,a,15,19);
    R2(a,b,c,d,0,3); R2(d,a,b,c,4,5); R2(c,d,a,b,8,9); R2(b,c,d,a,12,13);
    R2(a,b,c,d,1,3); R2(d,a,b,c,5,5); R2(c,d,a,b,9,9); R2(b,c,d,a,13,13);
    R2(a,b,c,d,2,3); R2(d,a,b,c,6,5); R2(c,d,a,b,10,9); R2(b,c,d,a,14,13);
    R2(a,b,c,d,3,3); R2(d,a,b,c,7,5); R2(c,d,a,b,11,9); R2(b,c,d,a,15,13);
    R3(a,b,c,d,0,3); R3(d,a,b,c,8,9); R3(c,d,a,b,4,11); R3(b,c,d,a,12,15);
    R3(a,b,c,d,2,3); R3(d,a,b,c,10,9); R3(c,d,a,b,6,11); R3(b,c,d,a,14,15);
    R3(a,b,c,d,1,3); R3(d,a,b,c,9,9); R3(c,d,a,b,5,11); R3(b,c,d,a,13,15);
    R3(a,b,c,d,3,3); R3(d,a,b,c,11,9); R3(c,d,a,b,7,11); R3(b,c,d,a,15,15);
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;
#undef F
#undef G
#undef H
#undef R1
#undef R2
#undef R3
}
static void hashbuf(const void *vp, size_t n, unsigned char out[16]) {
    const unsigned char *p=(const unsigned char*)vp;
    uint32_t h[4]={0x67452301u,0xefcdab89u,0x98badcfeu,0x10325476u};
    size_t full=n/64;
    for(size_t i=0;i<full;i++) md4_compress(h,p+64*i);
    unsigned char tail[128];
    size_t rem=n%64, total=(rem<56)?64:128;
    memset(tail,0,total); memcpy(tail,p+64*full,rem); tail[rem]=0x80;
    uint64_t bits=(uint64_t)n*8;
    for(int i=0;i<8;i++) tail[total-8+i]=(unsigned char)(bits>>(8*i));
    md4_compress(h,tail); if(total==128) md4_compress(h,tail+64);
    for(int i=0;i<4;i++) wr32le(out+4*i,h[i]);
}
static int in_range(const unsigned char*x,const unsigned char*lo,const unsigned char*hi){return memcmp(x,lo,21)>0&&memcmp(x,hi,21)<=0;}
static void add128(unsigned char s[16],const unsigned char x[16]){unsigned c=0;for(int i=15;i>=0;i--){unsigned v=s[i]+x[i]+c;s[i]=(unsigned char)v;c=v>>8;}}
static void mul_small128(unsigned char s[16],unsigned m){unsigned c=0;for(int i=15;i>=0;i--){unsigned v=s[i]*m+c;s[i]=(unsigned char)v;c=v>>8;}}
static void inc128(unsigned char s[16]){for(int i=15;i>=0;i--)if(++s[i])break;}
static void put32be(unsigned char*p,uint32_t x){p[0]=x>>24;p[1]=x>>16;p[2]=x>>8;p[3]=x;}
static void put32le(unsigned char*p,uint32_t x){p[0]=x;p[1]=x>>8;p[2]=x>>16;p[3]=x>>24;}
static unsigned char BYTE_HASH[256][16];
static uint32_t BYTE_HASHW[256][4];
static void init_byte_hash(void){for(int i=0;i<256;i++){unsigned char b=i;hashbuf(&b,1,BYTE_HASH[i]);for(int j=0;j<4;j++){const unsigned char*q=BYTE_HASH[i]+4*j;BYTE_HASHW[i][j]=((uint32_t)q[0]<<24)|((uint32_t)q[1]<<16)|((uint32_t)q[2]<<8)|q[3];}}}
static void add_byte_digests_fast(unsigned char s[16],const unsigned char block[256]){uint32_t w[4]={0};for(int i=0;i<256;i++){const uint32_t*d=BYTE_HASHW[block[i]];uint64_t z=(uint64_t)w[3]+d[3];w[3]=z;uint64_t c=z>>32;z=(uint64_t)w[2]+d[2]+c;w[2]=z;c=z>>32;z=(uint64_t)w[1]+d[1]+c;w[1]=z;c=z>>32;z=(uint64_t)w[0]+d[0]+c;w[0]=z;}for(int j=0;j<4;j++)put32be(s+4*j,w[j]);}
static void init_state(uint32_t t,int mode,unsigned char state[16]){
    unsigned char b4[4],block[256],d[16];memset(state,0,16);memset(block,0,sizeof block);
    switch(mode){
    case 0:put32be(state+12,t);break;case 1:put32le(state+12,t);break;case 2:put32be(state,t);break;case 3:put32le(state,t);break;
    case 4:for(int i=0;i<4;i++)put32be(state+4*i,t);break;case 5:for(int i=0;i<4;i++)put32le(state+4*i,t);break;
    case 10:put32be(b4,t);hashbuf(b4,4,state);break;case 11:put32le(b4,t);hashbuf(b4,4,state);break;
    case 12:put32be(b4,t);hashbuf(b4,4,state);mul_small128(state,64);break;case 13:put32le(b4,t);hashbuf(b4,4,state);mul_small128(state,64);break;
    case 14:for(int i=0;i<64;i++)put32be(block+4*i,t);hashbuf(block,256,state);break;case 15:for(int i=0;i<64;i++)put32le(block+4*i,t);hashbuf(block,256,state);break;
    case 16:put32be(block,t);hashbuf(block,256,state);break;case 17:put32le(block,t);hashbuf(block,256,state);break;
    case 18:put32be(block+252,t);hashbuf(block,256,state);break;case 19:put32le(block+252,t);hashbuf(block,256,state);break;
    case 20:case 21:if(mode==20)put32be(b4,t);else put32le(b4,t);for(int j=0;j<4;j++){hashbuf(&b4[j],1,d);mul_small128(d,64);add128(state,d);}break;
    case 22:{char q[32];int n=snprintf(q,sizeof q,"%u",t);hashbuf(q,n,state);break;}
    case 23:{char q[32];int n=snprintf(q,sizeof q,"%u",t);for(int i=0;i<256;i++)block[i]=q[i%n];hashbuf(block,256,state);break;}
    case 24:{char q[32];int n=snprintf(q,sizeof q,"%u",t);hashbuf(q,n,state);mul_small128(state,64);break;}
    default:{
        int per_byte=(mode>=50),base=per_byte?mode-20:mode;uint32_t x=t,A=0,C=0;int style=base%4;
        if(base>=30&&base<=33){A=214013u;C=2531011u;}else if(base>=34&&base<=37){A=1103515245u;C=12345u;}else if(base>=38&&base<=41){A=22695477u;C=1u;}else if(base==42||base==43){A=1664525u;C=1013904223u;style=(base==42?0:1);}else{fprintf(stderr,"unknown mode %d\n",mode);exit(2);}int pos=0;
        while(pos<256){x=A*x+C;uint32_t r=(base>=42)?x:((x>>16)&0x7fffu);if(style==0)block[pos++]=r;else if(style==1)block[pos++]=(base>=42)?(r>>24):(r>>7);else if(style==2){block[pos++]=r;if(pos<256)block[pos++]=r>>8;}else{block[pos++]=r>>8;if(pos<256)block[pos++]=r;}}
        if(per_byte)add_byte_digests_fast(state,block);else hashbuf(block,256,state);break;}
    }
}
static int scan_one(uint32_t t,int mode,int ncalls,int*which,int*callidx){unsigned char state[16],stream[16*128],dig[16],r[21];init_state(t,mode,state);int nbytes=24*ncalls,nd=(nbytes+15)/16;if(nd>128)return 0;for(int j=0;j<nd;j++){hashbuf(state,16,dig);memcpy(stream+16*j,dig,16);inc128(state);}for(int i=0;i<ncalls;i++){const unsigned char*raw=stream+24*i;memcpy(r,raw+3,21);r[0]&=7;r[20]|=1;if(in_range(r,lo1,hi1)){*which=1;*callidx=i;return 1;}if(in_range(r,lo2,hi2)){*which=2;*callidx=i;return 1;}}return 0;}
static void hex(const unsigned char*x,int n){for(int i=0;i<n;i++)printf("%02x",x[i]);}
int main(int argc,char**argv){
    if(argc==2&&!strcmp(argv[1],"--selftest")){unsigned char d[16];hashbuf("",0,d);hex(d,16);puts("");hashbuf("a",1,d);hex(d,16);puts("");return 0;}
    init_byte_hash();if(argc<6){fprintf(stderr,"usage: %s start end mode ncalls threads\n",argv[0]);return 2;}uint64_t start=strtoull(argv[1],0,0),end=strtoull(argv[2],0,0);int mode=atoi(argv[3]),ncalls=atoi(argv[4]),nth=atoi(argv[5]);
#ifdef _OPENMP
    omp_set_num_threads(nth);double t0=omp_get_wtime();
#else
    double t0=0;
#endif
    volatile int found=0;uint64_t ht=0;int hw=0,hi=0;
#pragma omp parallel for schedule(static)
    for(uint64_t x=start;x<end;x++){if(found)continue;int w=0,i=0;if(scan_one((uint32_t)x,mode,ncalls,&w,&i)){
#pragma omp critical
        {if(!found){found=1;ht=x;hw=w;hi=i;}}}}
#ifdef _OPENMP
    double t1=omp_get_wtime();
#else
    double t1=1;
#endif
    printf("hash=MD4 mode=%d start=%llu end=%llu ncalls=%d threads=%d elapsed=%.3f rate=%.0f/s found=%d",mode,(unsigned long long)start,(unsigned long long)end,ncalls,nth,t1-t0,(end-start)/(t1-t0),found);if(found)printf(" seed=%llu which=%d call=%d",(unsigned long long)ht,hw,hi);puts("");return found?0:1;
}
