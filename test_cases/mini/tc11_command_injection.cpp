// TC-11 | Category: SECURITY — Command Injection (HIGH) + syntax_error
// Threat : system() executes a shell command that may include attacker input.
//          Combined with a missing semicolon to also trigger the compiler.
// Detected by: compiler_runner._sanitize_code() blocks compilation outright,
//              and security_analyzer flags the system() call.

#include <cstdlib>
#include <iostream>
using namespace std;

int main() {
    string filename
    cout << "Enter filename to display: ";
    cin >> filename;
    string cmd = "cat " + filename;  // Dangerous: user controls shell argument
    system(cmd.c_str());             // HIGH: command injection risk
    return 0;
}
