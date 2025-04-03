Here I am creating a checklist/step-by-step workflow for manual code review of C software.

# VULNERABILITY HUNTING WORKFLOW

## Attack Surface Mapping
"Let's go with the ACID flow!" - Xeno Kovah.

- Check the functionality available to use (may be the vulnerability itself → privilege escalation)
- Check parameters under control
- Trace the parameter values from source to sink
- Identify memory operations on data under your control (strcpy, memcpy, etc.)
```sh
# We can use my semgrep rule to quickly identify all places where memory is copied:
semgrep --config memory-copy-buffer-overflow.yaml .
```

## Check Memory Management

- Sequential data writes within a loop with an ACID loop-{counter, exit condition}
- Array bound validations → Buffer- | Heap- Overflow
- Size calculations → Integer- overflow | underflow
- SIGNED parameters under your control → OOB (most of the time this is a bug, use unsigned values by default). SLAUGHTER SIGNED SIZES!
- Pointer arithmetic operations (out-of-bound- read|write)
- Heap management (malloc/free pairs) → use-after-free | double-free
- Inline ASM or JIT-related memory access for potential code execution

**Uninitialized Data Access (UDA):**

- Check for uninitialized stack/heap variables or memory regions (e.g., malloc without memset)
- Review code for variables used before initialization (e.g., conditional branches skipping initialization)

**Type Confusion (TyCo):**

- Identify improper type casting (e.g., void* cast to incompatible structs) or misuse of unions
- Check for JIT/scripting engines mishandling object types

**Use-After-Free (UAF):**

- Audit malloc/free pairs; ensure pointers are nullified after free
- Trace pointer lifetimes across function calls/threads

**Information Disclosure via Memory Operations:**

- Detect out-of-bound (OOB) reads via insufficient bounds checks (e.g., memcpy to user-controlled buffers)
- Review error paths for exposing uninitialized memory (e.g., returning stack structs without sanitization)

## Check Input Validation:

- Format String vulnerabilities (printf, scanf, etc.)
- Command Injection (system(), popen(), etc.)
- Path Traversal (unsanitized file paths)
- Null byte injection (truncation bugs)
- Encoding issues (Unicode/multibyte char handling)
- Regex failures (poorly validated input)
- Integer truncation issues (atoi, strtol returning unexpected values)
- Signed-to-unsigned conversion errors

## Check Concurrency Issues:

- Identify TOCTOU vulnerabilities (e.g., file metadata checked then used unsafely)
- Check shared resources (variables, files) accessed without locks (e.g., pthread_mutex)
- Review signal handlers for non-reentrant function calls (e.g., malloc in signal handlers)
- Deadlocks (improper locking sequences)
- Atomicity violations (non-atomic operations on shared resources)
- Use of non-thread-safe functions (strtok, asctime, etc.)
- Proper use of synchronization primitives (pthread_mutex, semaphores)
- Memory consistency issues (ensuring correct visibility of shared variables across threads)
- Signal handling vulnerabilities (unsafe use of signal() handlers)

## Check Error Handling:

- Ensure all system calls and library functions return values are checked
- Avoid silent failures and missing error logs
- Validate return codes from memory allocation functions (malloc, realloc)
- Ensure correct cleanup on error paths (prevent leaks and dangling pointers) → memory leaks
- Validate error messages/logs don't leak sensitive data (e.g., stack traces, internal paths)

## Check Cryptographic Usage:

- Custom crypto implementations (likely flawed)
- Hardcoded cryptographic keys or secrets
- Usage of non-vetted cryptographic libraries (OpenSSL, libsodium is good)
- Ensure secure randomness (/dev/urandom, RAND_bytes, avoid rand())
- Check encryption modes (avoid ECB mode, prefer CBC/GCM)
- Ensure proper key management (no exposure in logs, stack traces)
- Verify correct use of hash functions (avoid MD5, use SHA-256+)
- Ensure correct handling of certificates (avoid self-signed or weak TLS configurations)


# EXTENSIONS FOR VS CODE
* https://marketplace.visualstudio.com/items?itemName=AbdAlMoniem-AlHifnawy.c-call-hierarchy