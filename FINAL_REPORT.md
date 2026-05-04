# [CRITICAL] Memory Corruption via Global Buffer Overflow in Transaction Parsing (reformat_coins)

## Description
A critical global buffer overflow vulnerability exists in the Ledger App Binance during the parsing and formatting of transaction data for display. The vulnerability is located in the `reformat_coins` function within `src/lib/transaction_parser.c`, which uses unsafe string manipulation functions (`replace_word` and `fixed8_str_conv`) to "prettify" transaction fields.

When processing a "coins" object or other reformattable fields, the app copies a chunk of the transaction JSON into a global buffer `viewctl_DataValue` (declared in `src/view_common.c`). This buffer has a fixed size of `MAX_CHARS_PER_VALUE_LINE` (130 bytes). The `reformat_coins` function then performs multiple string expansions (e.g., replacing `denom:` with 9 spaces, or adding decimal points via `fixed8_str_conv`) without any bounds checking against the destination buffer's capacity.

An attacker can craft a transaction containing a long string of specific patterns (e.g., repeated `denom:` keys) that fits within the initial 130-byte chunk but expands significantly during reformatting, leading to a global buffer overflow of up to 60+ bytes.

## Affected Code Locations
- **File**: `src/lib/transaction_parser.c`
  - **Function**: `reformat_coins`
  - **Function**: `replace_word` (lacks bounds checking)
- **File**: `src/fixed8.c`
  - **Function**: `fixed8_str_conv` (expands string without bounds check)
- **File**: `src/view_common.c`
  - **Variable**: `viewctl_DataValue` (130-byte destination buffer)

## Impact: Critical
The overflow occurs in the global data section, allowing an attacker to overwrite adjacent critical state variables and control structures:

1.  **Arbitrary Code Execution (RCE)**: The overflow can overwrite function pointers such as `viewctl_ehReady`, `viewctl_ehExit`, and `viewctl_display_ux` in `src/view_common.c`. By redirecting these pointers to attacker-controlled code or ROP gadgets, an attacker can achieve full control over the device's execution flow.
2.  **Bypass "What You See is What You Sign" (WYSIWYS)**: The overflow overwrites `viewctl_Title` and other UI state variables, allowing an attacker to display fraudulent transaction information to the user while signing a different transaction.
3.  **Security Policy Bypass**: Depending on the linker's memory layout, the overflow can overwrite `viewed_bip32_path` in `src/app_main.c`. This variable is used to ensure the user has "seen" the address they are signing. Overwriting it allows signing for unauthorized derivation paths without user confirmation of the target address.

## Quantification and Reachability
- **Maximum Overflow**: The `update` function fills `viewctl_DataValue` with up to 129 characters. A payload containing 21 instances of `denom:` (126 chars) expands to 189 bytes during the first `replace_word` call. This results in an **overflow of 59 bytes** beyond the 130-byte buffer.
- **Memory Layout Evidence**: 
  In `src/view_common.c`, the following variables are adjacent:
  ```c
  volatile char viewctl_DataValue[130];
  volatile char viewctl_Title[22];
  int viewctl_DetailsCurrentPage;
  int viewctl_DetailsPageCount;
  int viewctl_ChunksIndex;
  int viewctl_ChunksCount;
  bool viewctl_SinglePage;
  viewctl_delegate_getData viewctl_ehGetData;
  viewctl_delegate_ready viewctl_ehReady; // CRITICAL TARGET
  viewctl_delegate_exit viewctl_ehExit;   // CRITICAL TARGET
  ```
  A 59-byte overflow completely overwrites `viewctl_Title` (22 bytes) and all subsequent integer state variables, reaching the critical function pointers.

## Reproduction Steps
1.  Compile the provided production-accurate PoC: `gcc poc_production.c -o poc`
2.  Run the PoC: `./poc`
3.  Observe that `viewctl_Title` is corrupted and `viewctl_ehReady` is successfully overwritten, demonstrating the control flow hijack potential.

## Remediation
1.  **Implement Bounds Checking**: Modify `replace_word`, `replace_chrs`, and `fixed8_str_conv` to take the destination buffer's maximum length as an argument and ensure no write occurs beyond that limit.
2.  **Use Safe String Functions**: Replace manual `memmove`/`memcpy` loops with safer alternatives that handle truncation gracefully.
3.  **Pre-validate Expansion**: In `reformat_coins`, calculate the required size after expansion before performing the operation, and truncate or reject the input if it exceeds 130 bytes.

---
**Proof of Concept (poc_production.c)**
(See attached file for the full source of the production-accurate simulation)
