// TC-14 | Category: SECURITY — Format String Vulnerability (HIGH) + missing_include
// Threat : printf() is called with a user-controlled string as the format
//          argument. An attacker can supply '%x' or '%n' specifiers to read
//          or write arbitrary memory.
// Detected by: security_analyzer diagnostic rules (format-not-a-string-literal)
//              + compiler warning -Wformat-security.
// Extra error: #include <cstring> is missing (strlen used without it).

#include <cstdio>

int main() {
    char userInput[128];
    fgets(userInput, sizeof(userInput), stdin);

    size_t len = strlen(userInput);    // missing_include: <cstring> not included
    if (len > 0 && userInput[len - 1] == '\n')
        userInput[len - 1] = '\0';

    printf(userInput);                 // HIGH: format string vulnerability
    return 0;
}
