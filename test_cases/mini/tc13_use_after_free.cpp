// TC-13 | Category: SECURITY — Use After Free (HIGH) + name_resolution error
// Threat : A pointer is deleted and then immediately dereferenced — undefined
//          behaviour. An attacker may exploit heap metadata corruption.
// Detected by: security_analyzer freed_vars dataflow tracker.
// Extra error: 'value' is also used without std:: prefix (name_resolution).

#include <iostream>
using namespace std;

int main() {
    int* ptr = new int(42);
    cout << "Value before delete: " << *ptr << endl;

    delete ptr;                       // ptr is freed here
    cout << "Value after delete: " << *ptr << endl;  // HIGH: use-after-free

    // Also: missing std:: on cout in a context where it is stripped
    int* ptr2 = new int(10);
    cout << value << endl;            // name_resolution: 'value' undeclared
    delete ptr2;
    return 0;
}
