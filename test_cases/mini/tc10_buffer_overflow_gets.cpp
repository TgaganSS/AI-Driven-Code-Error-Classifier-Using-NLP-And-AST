// TC-10 | Category: SECURITY — Buffer Overflow (CRITICAL)
// Threat : gets() reads user input with NO bounds checking.
//          An attacker can overflow the buffer and overwrite adjacent memory.
// Detected by: security_analyzer._scan_source_findings()
// Fix        : Replace with fgets() or std::string + std::getline.

#include <cstdio>

int main() {
    char username[32];
    printf("Enter username: ");
    gets(username);                   // CRITICAL: no bounds checking
    printf("Welcome, %s!\n", username);
    return 0;
}
