#include "APA.h"

#define RR(a,b) ((a>>b)^(a<<(64-b)))

/*Implementation of 2-round of Ascon without constants*/
uint64_t ASCON_2r_hash(uint64_t m64_msg) {

	uint64_t x[5] = { 0, };
	uint64_t xtemp;
	/* init */
	x[0] = m64_msg;
	/* round constant */
	//s->x[2] ^= C;
	/* s-box layer */
	x[0] ^= x[4];
	x[4] ^= x[3];
	x[2] ^= x[1];
	xtemp = x[0] & ~x[4];
	x[0] ^= x[2] & ~x[1];
	x[2] ^= x[4] & ~x[3];
	x[4] ^= x[1] & ~x[0];
	x[1] ^= x[3] & ~x[2];
	x[3] ^= xtemp;
	x[1] ^= x[0];
	x[3] ^= x[2];
	x[0] ^= x[4];
	x[2] = ~x[2];

	/* linear layer */
	xtemp = x[0] ^ RR(x[0], 9);
	x[0] ^= RR(xtemp, 19);
	xtemp = x[1] ^ RR(x[1], 22);
	x[1] ^= RR(xtemp, 39);
	xtemp = x[2] ^ RR(x[2], 5);
	x[2] ^= RR(xtemp, 1);
	xtemp = x[3] ^ RR(x[3], 7);
	x[3] ^= RR(xtemp, 10);
	xtemp = x[4] ^ RR(x[4], 34);
	x[4] ^= RR(xtemp, 7);

	/* round constant */
	//s->x[2] ^= C;
	/* s-box layer */
	x[0] ^= x[4];
	x[4] ^= x[3];
	x[2] ^= x[1];
	xtemp = x[0] & ~x[4];
	x[0] ^= x[2] & ~x[1];
	x[2] ^= x[4] & ~x[3];
	x[4] ^= x[1] & ~x[0];
	x[1] ^= x[3] & ~x[2];
	x[3] ^= xtemp;
	x[1] ^= x[0];
	x[3] ^= x[2];
	x[0] ^= x[4];
	x[2] = ~x[2];

	/* linear layer */
	xtemp = x[0] ^ RR(x[0], 9);
	x[0] ^= RR(xtemp, 19);
	xtemp = x[1] ^ RR(x[1], 22);
	x[1] ^= RR(xtemp, 39);
	xtemp = x[2] ^ RR(x[2], 5);
	x[2] ^= RR(xtemp, 1);
	xtemp = x[3] ^ RR(x[3], 7);
	x[3] ^= RR(xtemp, 10);
	xtemp = x[4] ^ RR(x[4], 34);
	x[4] ^= RR(xtemp, 7);

	return x[0];
}

/*Implementation of 2-round of Ascon without constants*/
/*The linear layer of the last round is omitted*/
uint64_t __ASCON_2r_for_attack(uint64_t m64_msg) {
	uint64_t x[5] = { 0, };
	uint64_t xtemp;
	/* init/round constant(skip)/1 round s-box*/
	x[0] = x[3] = x[1] = m64_msg;
	x[2] = 0xFFFFFFFFFFFFFFFF;

	/* linear layer */
	xtemp = x[0] ^ RR(x[0], 9);
	x[0] ^= RR(xtemp, 19);
	xtemp = x[1] ^ RR(x[1], 22);
	x[1] ^= RR(xtemp, 39);
	xtemp = x[2] ^ RR(x[2], 5);
	x[2] ^= RR(xtemp, 1);
	xtemp = x[3] ^ RR(x[3], 7);
	x[3] ^= RR(xtemp, 10);
	xtemp = x[4] ^ RR(x[4], 34);
	x[4] ^= RR(xtemp, 7);

	/* round constant */
	//s->x[2] ^= C;
	/* s-box layer */
	x[0] ^= x[4];
	x[4] ^= x[3];
	x[2] ^= x[1];
	xtemp = x[0] & ~x[4];
	x[0] ^= x[2] & ~x[1];
	x[2] ^= x[4] & ~x[3];
	x[4] ^= x[1] & ~x[0];
	x[1] ^= x[3] & ~x[2];
	x[3] ^= xtemp;
	x[1] ^= x[0];
	x[3] ^= x[2];
	x[0] ^= x[4];
	x[2] = ~x[2];

	return x[0];
}
uint64_t inv_linearlayer(uint64_t hash_val) {
	unsigned char inverse[] = { 0,  1,  4,  7, 11, 14, 17, 19, 20, 22, 23, 25, 26, 28, 31, 34, 37, 39, 40, 42, 43, 45, 46, 47, 49, 50, 52, 53, 55, 58, 61 };
	
	uint64_t ret = 0;
	unsigned char binhash[64] = { 0, };
	unsigned char binret[64] = { 0, };
	int i, j;
	
	for (i = 0; i < 64; i++) {
		binhash[i] = (hash_val >> (63 - i)) & 1;
	}
	for (i = 0; i < 64; i++) {
		for (j = 0; j < 31; j++)
			binret[i] ^= binhash[(inverse[j] + i) % 64];
	}

	
	for (i = 0; i < 64; i++) {
		ret |= ((uint64_t)binret[i]) << (63 - i);
	}
	return ret;
}
