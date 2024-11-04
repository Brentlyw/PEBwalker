# PEBwalker
A PEB walker that resolves function addresses via runtime hash comparison, avoiding static imports.

## Flow
1. Calculates hash for target module & function
2. Access process environment block (PEB)
3. Walk loaded module list
4. Match module via hash
5. Parses module exports
6. Resolves functions via hash
7. Returns function pointer of target
8. Profit

## Detections
*At the time of writing, no engines detect this code snippet as malicious, as it is really not by itself.*

## Example Usage
```rust
//Create UTF-16 hash for module
let target_lib: Vec<u16> = "ntdll.dll".encode_utf16().collect();
let lib_sum = calc_wide_checksum(&target_lib);

//Create hash for target function
let target_func = calc_checksum(b"NtAllocateVirtualMemory");

//Resolve func pointer
let routine_ptr = find_routine(lib_sum, target_func);
