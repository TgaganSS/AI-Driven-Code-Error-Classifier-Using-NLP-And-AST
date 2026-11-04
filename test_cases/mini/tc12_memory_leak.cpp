// TC-12 | Category: SECURITY — Potential Memory Leak (MEDIUM)
// Threat : malloc() allocates a buffer inside the loop but free() is never
//          called within the same scope — the memory leaks on every iteration.
// Detected by: security_analyzer scope-stack malloc/free tracker.
// Note  : The code compiles cleanly — this is a pure security finding.

#include <cstdlib>
#include <cstdio>

void processRecord(int id) {
    char* buffer = (char*)malloc(256);  // Allocated but never freed
    if (buffer == nullptr) return;
    snprintf(buffer, 256, "Processing record %d", id);
    printf("%s\n", buffer);
    // Missing: free(buffer);
}

int main() {
    for (int i = 0; i < 5; i++) {
        processRecord(i);
    }
    return 0;
}
