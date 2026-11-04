// TC-15 | Category: COMBINED — Multiple errors + Multiple security threats
// This is a comprehensive stress-test for the full pipeline.
//
// Compilation Errors:
//   (a) missing_include  : 'string' used without #include <string>
//   (b) syntax_error     : Missing semicolon on 'int score'
//   (c) uninitialized    : 'grade' used uninitialized
//
// Security Threats:
//   (d) Buffer Overflow  : strcpy() with no bounds check (HIGH)
//   (e) Unbounded Input  : scanf("%s") without width limit (HIGH)
//   (f) Weak Randomness  : rand() used to generate an auth token (HIGH)
//   (g) Integer Overflow : score addition may overflow int (HIGH)

#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
// Missing: #include <string>

using namespace std;

int main() {
    char name[16];
    char fullName[16];

    // (e) Unbounded scanf — no width limit on %s
    scanf("%s", name);

    // (d) Buffer overflow — strcpy does not check destination size
    strcpy(fullName, name);

    // (b) Missing semicolon
    int score
    score = 2000000000;

    // (g) Integer overflow — adding to a near-max int
    int bonus = 100000000;
    int total = score + bonus;       // Overflow risk

    // (c) Uninitialized variable
    char grade;
    if (total > 1000000000)
        grade = 'A';
    cout << "Student: " << fullName
         << " | Score: " << total
         << " | Grade: " << grade << endl;  // grade may be uninitialized

    // (f) Weak randomness used as auth token near security-sensitive label
    int token = rand();    // key generated with weak rand()
    printf("Session token (key): %d\n", token);

    // (a) string type used without including <string>
    string message = "Evaluation complete.";
    cout << message << endl;

    return 0;
}
