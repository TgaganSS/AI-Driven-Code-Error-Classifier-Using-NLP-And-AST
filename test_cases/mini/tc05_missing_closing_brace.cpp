// TC-05 | Category: missing_closing_brace
// Error : The function body is missing its closing '}'.
// The auto-healer uses a brace-depth stack parser to insert the missing brace.

#include <iostream>
using namespace std;

void greet(string name) {
    if (name.empty()) {
        cout << "Hello, Stranger!" << endl;
    } else {
        cout << "Hello, " << name << "!" << endl;
    }
// Missing closing brace for greet()

int main() {
    greet("Alice");
    greet("");
    return 0;
}
