// TC-07 | Category: syntax_error (keyword typo)
// Error : 'retrun' is not a C++ keyword — it is a transposition of 'return'.
// The auto-healer applies Levenshtein-distance spell correction.

#include <iostream>
using namespace std;

int add(int a, int b) {
    retrun a + b;       // Typo: 'retrun' instead of 'return'
}

int main() {
    cout << "3 + 4 = " << add(3, 4) << endl;
    return 0;
}
