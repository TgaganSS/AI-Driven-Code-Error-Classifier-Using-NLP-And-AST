"""Generate two ~8,800-line C++ files for the scale demo.

    python tools/make_big_tests.py /content/big
big_errors.cpp   : syntax + lexical + undeclared-variable errors buried at the end
big_security.cpp : compiles fine, contains classic vulnerabilities
"""
import os
import sys

HDR = "#include <iostream>\n#include <cstring>\n#include <cstdio>\n#include <cstdlib>\nusing namespace std;\n\n"


def funcs(n):
    return "".join(f"""int calc_{i}(int a, int b) {{
    int r = 0;
    for (int k = 0; k < 4; k++) {{
        r += (a * k + b) % 7;
    }}
    if (r > {i % 13}) {{ r -= {i % 5}; }}
    return r;
}}
""" for i in range(n))


ERRORS = """
int bad_syntax(int x) {
    int y = x * 2
    return y;
}

int bad_lexical() {
    const char* s = "unterminated string;
    return 0;
}

int bad_token() {
    int v = 5 @ 3;
    return v;
}

int bad_undeclared() {
    return undefined_var + 1;
}

int main() {
    cout << calc_1(2,3) << endl;
    return 0;
}
"""

SECURITY = """
void vuln_copy(const char* name) {
    char buf[8];
    strcpy(buf, name);
    printf("hello %s\\n", buf);
}
void vuln_fmt(const char* msg) { printf(msg); }
void vuln_free() {
    int* p = new int[4];
    delete p;
    char* q = (char*)malloc(8);
    if (!q) return;
    free(q);
    free(q);
}
int main(int argc, char** argv) {
    if (argc > 1) { vuln_copy(argv[1]); vuln_fmt(argv[1]); }
    vuln_free();
    cout << calc_1(2,3) << endl;
    return 0;
}
"""

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "big"
    os.makedirs(out, exist_ok=True)
    for name, tail in (("big_errors.cpp", ERRORS), ("big_security.cpp", SECURITY)):
        with open(os.path.join(out, name), "w") as f:
            f.write(HDR + funcs(1100) + tail)
        print(name, sum(1 for _ in open(os.path.join(out, name))), "lines")
