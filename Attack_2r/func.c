#include "APA.h"

#define NEED_GUESS 0xFF

void preprocess_phase(st* parms);

void __final_check(const st parms, unsigned char gs_msg_bit[64], unsigned char deter[64], uint64_t target) {
    int i, cnt = 0, bit;
    uint64_t msg = 0, check;
    for (i = 0; i < 64; i++) {
        msg <<= 1;
        bit = gs_msg_bit[i];
        if (bit == 0xff)
            bit = deter[cnt++];
        msg |= bit;
    }
    check = __ASCON_2r_for_attack(msg);
    if (check == target) {
        printf("FIND -> msg = 0x%llX\n", msg);
        exit(1);
    }
}

void __init_eqs_verEQS(const st parms, const unsigned char gs_msg_bit[64], unsigned char ansbuff[64], EQS *eqs) {
    unsigned int i, j,cnt,var, tmp, eqcnt=0;
    unsigned char* t_lst0, * t_lst1, * t_lst3;

    parms.idx_guess_bits_en.arr[parms.lst0[i][0]];
    
    for (i = 0; i < parms.row; i++) {
        cnt = 0;
        eqcnt = 0;
        t_lst0 = parms.lst0[parms.idx_lin_gen_bits.arr[i]];
        t_lst1 = parms.lst1[parms.idx_lin_gen_bits.arr[i]];
        t_lst3 = parms.lst3[parms.idx_lin_gen_bits.arr[i]];
        
        if (parms.idx_guess_bits_en.arr[t_lst0[0]] && parms.idx_guess_bits_en.arr[t_lst0[1]] && parms.idx_guess_bits_en.arr[t_lst0[2]]) {
            var = gs_msg_bit[t_lst0[0]] ^ gs_msg_bit[t_lst0[1]] ^ gs_msg_bit[t_lst0[2]];
            if (var) {
                cnt = gs_msg_bit[t_lst0[0]] ^ gs_msg_bit[t_lst0[1]] ^ gs_msg_bit[t_lst0[2]]
                    ^ gs_msg_bit[t_lst1[0]] ^ gs_msg_bit[t_lst1[1]] ^ gs_msg_bit[t_lst1[2]]
                    ^ gs_msg_bit[t_lst3[0]] ^ gs_msg_bit[t_lst3[1]] ^ gs_msg_bit[t_lst3[2]];
                cnt = (cnt ^ (cnt >> 1)) & 1; //Remove NEED_GUESS
                eqs->e[i].ans =  ansbuff[i] ^ cnt ^ 1;

                for (j = 0; j < parms.total_not_included_idx.lst[i]._3.size; j++) {
                    tmp = parms.total_not_included_idx.lst[i]._3.arr[j];
                    if (gs_msg_bit[tmp] == NEED_GUESS)
                        eqs->e[i].q[eqcnt++] = parms.ccomp_idx[tmp];
                }
                for (j = 0; j < parms.total_not_included_idx.lst[i]._1.size; j++) {
                    tmp = parms.total_not_included_idx.lst[i]._1.arr[j];
                    if (gs_msg_bit[tmp] == NEED_GUESS)
                        eqs->e[i].q[eqcnt++] = parms.ccomp_idx[tmp];
                }
                eqs->e[i].size = eqcnt;
            }
            else {
                cnt = gs_msg_bit[t_lst3[0]] ^ gs_msg_bit[t_lst3[1]] ^ gs_msg_bit[t_lst3[2]];
                cnt = (cnt ^ (cnt >> 1)) & 1; //Remove NEED_GUESS
                eqs->e[i].ans = ansbuff[i] ^ cnt ^ 1;
                
                for (j = 0; j < parms.total_not_included_idx.lst[i]._3.size; j++) {
                    tmp = parms.total_not_included_idx.lst[i]._3.arr[j];
                    if (gs_msg_bit[tmp] == NEED_GUESS)
                        eqs->e[i].q[eqcnt++] = parms.ccomp_idx[tmp];
                }
                eqs->e[i].size = eqcnt;
            }
        }
        else {
            var = gs_msg_bit[t_lst1[0]] ^ gs_msg_bit[t_lst1[1]] ^ gs_msg_bit[t_lst1[2]];
            if (var) {
                cnt = gs_msg_bit[t_lst3[0]] ^ gs_msg_bit[t_lst3[1]] ^ gs_msg_bit[t_lst3[2]];
                cnt = (cnt ^ (cnt >> 1)) & 1; //Remove NEED_GUESS
                eqs->e[i].ans = ansbuff[i] ^ cnt ^ 1;

                for (j = 0; j < parms.total_not_included_idx.lst[i]._3.size; j++) {
                    tmp = parms.total_not_included_idx.lst[i]._3.arr[j];
                    if (gs_msg_bit[tmp] == NEED_GUESS) 
                        eqs->e[i].q[eqcnt++] = parms.ccomp_idx[tmp];
                }
                eqs->e[i].size = eqcnt;
            }
            else {
                cnt = gs_msg_bit[t_lst0[0]] ^ gs_msg_bit[t_lst0[1]] ^ gs_msg_bit[t_lst0[2]]
                    ^ gs_msg_bit[t_lst3[0]] ^ gs_msg_bit[t_lst3[1]] ^ gs_msg_bit[t_lst3[2]];
                cnt = (cnt ^ (cnt >> 1)) & 1; //Remove NEED_GUESS
                eqs->e[i].ans = ansbuff[i] ^ cnt ^ 1;

                for (j = 0; j < parms.total_not_included_idx.lst[i]._0.size; j++) {
                    tmp = parms.total_not_included_idx.lst[i]._0.arr[j];
                    if (gs_msg_bit[tmp] == NEED_GUESS)
                        eqs->e[i].q[eqcnt++] = parms.ccomp_idx[tmp];
                }
                for (j = 0; j < parms.total_not_included_idx.lst[i]._3.size; j++) {
                    tmp = parms.total_not_included_idx.lst[i]._3.arr[j];
                    if (gs_msg_bit[tmp] == NEED_GUESS)
                        eqs->e[i].q[eqcnt++] = parms.ccomp_idx[tmp];
                }
                eqs->e[i].size = eqcnt;
            }
        }

    }
}

int __init_deter_verEQS(unsigned char* deter, EQS* eqs, unsigned char* original) {
    int i, j;

    for (i = 0; i < eqs->size; i++) {
        original[i] = eqs->e[i].size;

        if (eqs->e[i].size == 0) {
            if (eqs->e[i].ans)
                return 0;
        }
        else if (eqs->e[i].size == 1) {
            if (deter[eqs->e[i].q[0]] == 0xff) {
                deter[eqs->e[i].q[0]] = eqs->e[i].ans;
                eqs->e[i].q[0] = 0xff;
                eqs->e[i].ans = 0;
                eqs->e[i].size = 0;
                original[i] = 0;
            }
            else {
                if (deter[eqs->e[i].q[0]] == eqs->e[i].ans) {
                    eqs->e[i].q[0] = 0xff;
                    eqs->e[i].ans = 0;
                    eqs->e[i].size = 0;
                    original[i] = 0;
                }
                else
                    return 0;
            }
        }
        else {
            for (j = 0; j < original[i]; j++) {
                if (deter[eqs->e[i].q[j]] != 0xff) {
                    eqs->e[i].ans ^= deter[eqs->e[i].q[j]];
                    eqs->e[i].q[j] = 0xff;
                    (eqs->e[i].size)--;
                }
            }
            if (eqs->e[i].size == 0) {
                if (eqs->e[i].ans)
                    return 0;
                else {
                    original[i] = 0;
                }
            }
        }


    }
    return 1;
}

int __update_deter_verEQS(unsigned char* deter, EQS* eqs, unsigned char* original, int* remain) {
    int i, j;
    for (i = 0; i < eqs->size; i++) {
        if (eqs->e[i].size == 0) {
            if (eqs->e[i].ans)
                return 0;
        }
        else if (eqs->e[i].size == 1) {
            for (j = 0; j < original[i]; j++) {
                if (eqs->e[i].q[j] == 0xff)continue;

                if (deter[eqs->e[i].q[j]] == 0xff) {
                    deter[eqs->e[i].q[j]] = eqs->e[i].ans;
                    eqs->e[i].q[j] = 0xff;
                    eqs->e[i].ans = 0;
                    eqs->e[i].size = 0;
                    original[i] = 0;
                    (*remain)--;
                    break;
                }

                if (deter[eqs->e[i].q[j]] == eqs->e[i].ans) {
                    eqs->e[i].q[j] = 0xff;
                    eqs->e[i].ans = 0;
                    eqs->e[i].size = 0;
                    original[i] = 0;
                    (*remain)--;
                    break;
                }
                return 0;
            }
        }
        else {
            for (j = 0; j < original[i]; j++) {
                if (eqs->e[i].q[j] == 0xff)continue;
                if (deter[eqs->e[i].q[j]] != 0xff) {
                    eqs->e[i].ans ^= deter[eqs->e[i].q[j]];
                    eqs->e[i].q[j] = 0xff;
                    (eqs->e[i].size)--;
                    (*remain)--;
                }
            }
            if (eqs->e[i].size == 0) {
                if (eqs->e[i].ans)
                    return 0;
                else {
                    original[i] = 0;
                }
            }
        }
    }
    return 1;
}

void __guess_phase_verEQS(const st parms, unsigned char gs_msg_bit[64], unsigned char deter[64], unsigned char original[64], EQS eqs, uint64_t target_val) {

    int i, j, flag,fflag;
    int remain1, remain2;
    unsigned char ndeter[64];
    unsigned char noriginal[64];
    EQS tmpEQS;
    
    flag = 0;
    for (i = 0; i < parms.row; i++) {
        if (deter[i] == 0xff) {
            flag = 1;
            break;
        }
    }
    if (flag) {
        memcpy(ndeter, deter, 64);
        memcpy(noriginal, original, 64);
        memcpy(&tmpEQS, &eqs, sizeof(EQS));
        ndeter[i] = 0;
        fflag = 1;
        remain2 = 4096;
        do {
            remain1 = remain2;
            if (!__update_deter_verEQS(ndeter, &tmpEQS, noriginal, &remain2)) {
                fflag=0;
                break;
            }
        } while (remain1 != remain2);
        if (fflag) {
            __guess_phase_verEQS(parms, gs_msg_bit, ndeter, noriginal, tmpEQS, target_val);
        }

        memcpy(ndeter, deter, 64);
        memcpy(noriginal, original, 64);
        memcpy(&tmpEQS, &eqs, sizeof(EQS));
        ndeter[i] = 1;
        fflag = 1;
        remain2 = 4096;
        do {
            remain1 = remain2;
            if (!__update_deter_verEQS(ndeter, &tmpEQS, noriginal, &remain2)) {
                fflag = 0;
                break;
            }
        } while (remain1 != remain2);
        if (fflag) {
            __guess_phase_verEQS(parms, gs_msg_bit, ndeter, noriginal, tmpEQS, target_val);
        }
    }
    else {
        __final_check(parms, gs_msg_bit, deter, target_val);
    }
}


void guess_phase(const st parms, uint64_t gs_var, uint64_t target_val) {
    unsigned char target_list[64] = { 0, };
    unsigned char matrix[64][64] = { 0, };
    int i, j;
    unsigned char gs_msg_bit[64] = {0,};
    unsigned char ansbuff[64] = { 0, };


    for (i = 0; i < 64; i++)
        target_list[i] = (target_val >> (63 - i)) & 1;

    memset(gs_msg_bit, NEED_GUESS, 64);

    for (i = 0; i < parms.idx_guess_bits.size; i++)
        gs_msg_bit[parms.idx_guess_bits.arr[i]] = (gs_var>> i) & 1;


    for (i = 0; i < parms.row; i++)
        ansbuff[i] = target_list[parms.idx_lin_gen_bits.arr[i]];

    EQS eqs = { NULL };
    eqs.size = parms.row;
   __init_eqs_verEQS(parms, gs_msg_bit, ansbuff ,&eqs);

   
   unsigned char deterEQS[64];
   memset(deterEQS, 0xff, 64);
   unsigned char original[64] = { 0, };

   int remain1, remain2;
   if (!__init_deter_verEQS(deterEQS, &eqs, original))
       return;
   remain2 = 4096;
   do {
       remain1 = remain2;
       if (!__update_deter_verEQS(deterEQS, &eqs, original, &remain2))
           return;
   } while (remain1 != remain2);

   __guess_phase_verEQS(parms, gs_msg_bit, deterEQS, original, eqs, target_val);

}


void preprocess_phase(st* parms) {
    int i, cnt, ccnt, cccnt, j, k, flag, fflag, ffflag;
    /* gen idx_guess_bits */
    for (i = 0; i < parms->idx_guess_bits.size; i++) {
        parms->idx_guess_bits_en.arr[parms->idx_guess_bits.arr[i]] = 1;
    }

    ccnt = 0;
    for (i = 0; i < 64; i++) {
        parms->ccomp_idx[i] = -1;
        if (parms->idx_guess_bits_en.arr[i])
            continue;
        else {
            parms->ccomp_idx[i] = ccnt;
            parms->ccomp.arr[ccnt++] = i;
        }
    }
    parms->ccomp.size = ccnt;

    /* gen total_not_incluse_idx */
    parms->total_not_included_idx.size = parms->idx_lin_gen_bits.size;
    for (i = 0; i < parms->total_not_included_idx.size; i++) {
        cnt = 0;
        ccnt = 0;
        cccnt = 0;
        for (j = 0; j < 3; j++) {
            flag = 1;
            fflag = 1;
            ffflag = 1;
            for (k = 0; k < parms->idx_guess_bits.size; k++) {
                if (parms->lst0[parms->idx_lin_gen_bits.arr[i]][j] == parms->idx_guess_bits.arr[k])
                    flag = 0;
                if (parms->lst1[parms->idx_lin_gen_bits.arr[i]][j] == parms->idx_guess_bits.arr[k])
                    fflag = 0;
                if (parms->lst3[parms->idx_lin_gen_bits.arr[i]][j] == parms->idx_guess_bits.arr[k])
                    ffflag = 0;
            }
            if (flag)
                parms->total_not_included_idx.lst[i]._0.arr[cnt++] = parms->lst0[parms->idx_lin_gen_bits.arr[i]][j];
            if (fflag)
                parms->total_not_included_idx.lst[i]._1.arr[ccnt++] = parms->lst1[parms->idx_lin_gen_bits.arr[i]][j];
            if (ffflag)
                parms->total_not_included_idx.lst[i]._3.arr[cccnt++] = parms->lst3[parms->idx_lin_gen_bits.arr[i]][j];

        }
        parms->total_not_included_idx.lst[i]._0.size = cnt;
        parms->total_not_included_idx.lst[i]._1.size = ccnt;
        parms->total_not_included_idx.lst[i]._3.size = cccnt;

    }
    /* matrix size */
    parms->row = parms->idx_lin_gen_bits.size;
    parms->col = parms->ccomp.size + 1;
}



void start_attack(st parms, uint64_t target_hash, uint64_t start, uint64_t end) {
	/*Encoding input into suitable form for attack*/
    preprocess_phase(&parms);
    
    uint64_t target_val = inv_linearlayer(target_hash);
    long long gs_var;

    #pragma omp parallel shared(parms, target_val)
    {
        #pragma omp for
        for (gs_var = start; gs_var < end; gs_var++) {
			/*Guessing unguessed bits*/
            guess_phase(parms, gs_var, target_val);
        }
    }   

}