#pragma once
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdint.h>
#include<omp.h>
typedef struct _3byte {
	unsigned char arr[3];
	int size;
};
typedef struct _ldxs {
	struct _3byte _0;
	struct _3byte _1;
	struct _3byte _3;
};
typedef struct _nidx{
	struct _ldxs lst[64];
	int size;
}nidx;
typedef struct _bytes {
	unsigned char arr[64];
	int size;
} bytes;



typedef struct _eq {
	unsigned char q[64];
	unsigned char  ans;
	int size;
};
typedef struct _eqs {
	struct _eq e[64];
	unsigned char expired[64];
	int size;
}EQS;


typedef struct _node {
	int eq;
	struct _node* next;
}NODE;

typedef struct _nodelist {
	NODE* curl;
	int ans;
	int size;
	struct _nodelist* next;
}NODELIST;



typedef struct _state {
	bytes idx_lin_gen_bits;
	bytes idx_guess_bits_en;
	bytes idx_guess_bits;
	bytes ccomp;
	unsigned char ccomp_idx[64];
	nidx total_not_included_idx;
	/*fixed size value*/
	unsigned char lst0[64][3];
	unsigned char lst1[64][3];
	unsigned char lst3[64][3];
	int row;
	int col;
}st;

uint64_t  ASCON_2r_hash(uint64_t m64_msg);
uint64_t __ASCON_2r_for_attack(uint64_t m64_msg);
uint64_t inv_linearlayer(uint64_t hash_val);
void start_attack(st parms, uint64_t target_hash, uint64_t start, uint64_t end);



