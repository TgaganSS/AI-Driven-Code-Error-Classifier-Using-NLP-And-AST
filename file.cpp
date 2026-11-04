// TC-16 | Category: redefinition (compile error) + Double Free (SECURITY HIGH)
//
// Compilation Error:
//   (a) redefinition — the function 'computeScore' is defined twice in the
//       same translation unit. The compiler rejects the second definition.
//       The classifier should label this 'redefinition' with high confidence.
//
// Security Threat:
//   (b) Double Free — 'data' is deleted at the end of the first branch AND
//       again at the end of main. On a real heap this causes undefined
//       behaviour and is exploitable via heap metadata corruption.
//       Detected by: security_analyzer freed_vars dataflow tracker.
//
// Expected pipeline behaviour:
//   Compiler flags (a) first; the security analyzer flags (b) independently
//   via its static scan pass even if the file does not compile cleanly.

#include <iostream>
using namespace std;

// First (correct) definition
int computeScore(int base, int bonus) {
    return base + bonus;
}

// Duplicate definition — redefinition error
computeScore(int base, int bonus) {
    return base * bonus;      // Different body — still a redefinition
}

int main() {
    int* data = new int(100);

    int score = computeScore(*data, 25);
    cout << "Score: " << score << endl;

    if (score > 110) {
        delete data;          // First delete — conditionally executed
        cout << "High score! Memory released in branch." << endl;
    }

    // Double free: data is deleted again unconditionally,
    // even though it may already have been freed above.
    delete data;              // HIGH: potential double free

    return 0;
}
