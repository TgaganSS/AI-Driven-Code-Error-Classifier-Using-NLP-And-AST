"""Blind holdout for the security analyzer (written after tuning; see OPTIMIZATION.md).

Run: python benchmarks/eval_security.py
"""
# Blind holdout: written AFTER the analyzer was tuned, run once, results reported as-is.
H = "#include <cstdio>\n#include <cstdlib>\n#include <cstring>\n#include <iostream>\n#include <string>\n#include <vector>\n#include <fstream>\nusing namespace std;\n"
VULN = [
("b01_login_overflow", {120,787}, """
struct User { char name[16]; int admin; };
void greet(User* u, const char* input) {
    strcpy(u->name, input);          // classic struct-field overflow
    printf("hello %s\\n", u->name);
}
int main(int argc, char** argv) { User u{}; greet(&u, argv[1]); return 0; }"""),
("b02_log_format", {134}, """
void logmsg(const char* fmt) { printf(fmt); printf("\\n"); }
int main(int argc, char** argv) { if (argc > 1) logmsg(argv[1]); return 0; }"""),
("b03_cmd_build", {78}, """
int main() {
    string host;
    cin >> host;
    string cmd = "ping -c 1 " + host;
    system(cmd.c_str());
    return 0;
}"""),
("b04_read_loop_overflow", {120,787,193}, """
int main() {
    char line[32];
    int n = 0;
    int c;
    while ((c = getchar()) != EOF) { line[n++] = (char)c; }
    line[n] = 0;
    return n;
}"""),
("b05_leak_in_loop", {401}, """
void work(int n) {
    for (int i = 0; i < n; i++) {
        char* buf = (char*)malloc(128);
        if (!buf) return;
        buf[0] = 'x';
    }
}"""),
("b06_copy_len_from_user", {119,129,787}, """
void copy(const char* src) {
    char dst[20];
    int len;
    cin >> len;
    memcpy(dst, src, len);
    puts(dst);
}"""),
("b07_path_open", {22}, """
int main(int argc, char** argv) {
    ifstream f(argv[1]);
    string s;
    getline(f, s);
    cout << s;
    return 0;
}"""),
("b08_hardcoded_db", {798}, """
string connect() {
    string password = "Sup3rS3cretDBpass!";
    return "host=db;user=root;pass=" + password;
}"""),
("b09_double_free_branch", {415}, """
void f(int x) {
    int* p = new int(5);
    if (x) { delete p; }
    delete p;
}"""),
("b10_uaf_vector_ptr", {416}, """
void f() {
    char* s = (char*)malloc(16);
    if (!s) return;
    strcpy(s, "abc");
    free(s);
    printf("%s\\n", s);
}"""),
("b11_array_param_index", {129,787}, """
int table[16];
int lookup() {
    int idx;
    scanf("%d", &idx);
    return table[idx];
}"""),
("b12_alloc_mult", {190,789}, """
int* make(int count) {
    int* a = (int*)malloc(count * sizeof(int));
    return a;
}"""),
("b13_weak_hash", {327}, """
void hashpw(const char* pw, unsigned char* out) { MD5((const unsigned char*)pw, strlen(pw), out); }"""),
("b14_token_rand", {338,337}, """
string sessionToken() {
    srand(time(NULL));
    string t;
    for (int i = 0; i < 16; i++) t += "0123456789abcdef"[rand() % 16];
    return t;
}"""),
("b15_gets_like_scanf", {120}, """
void readName() {
    char name[10];
    printf("name: ");
    scanf("%s", name);
    printf("hi %s\\n", name);
}"""),
("b16_strncpy_term", {170}, """
void f(const char* in) {
    char buf[10];
    strncpy(buf, in, sizeof(buf));
    printf("%s", buf);
}"""),
("b17_env_to_system", {78}, """
int main() {
    const char* d = getenv("WORKDIR");
    char cmd[128];
    snprintf(cmd, sizeof cmd, "ls %s", d);
    system(cmd);
}"""),
("b18_new_mismatch", {762}, """
class Buf { public: int* d; Buf() { d = new int[64]; } ~Buf() { delete d; } };"""),
("b19_off_by_one_copy", {787,120,193}, """
void f() {
    char name[8];
    const char* src = "12345678";
    memcpy(name, src, 9);
}"""),
("b20_tmpfile", {377}, """
void f() { char* t = tmpnam(NULL); FILE* fp = fopen(t, "w"); if (fp) fclose(fp); }"""),
]
SAFE = [
("s01_class_string", """
class Greeter { string name_; public: explicit Greeter(string n): name_(std::move(n)) {} string hi() const { return "hi " + name_; } };
int main() { Greeter g("a"); cout << g.hi() << "\\n"; }"""),
("s02_bounded_copy", """
void f(const char* in) { char b[16]; snprintf(b, sizeof b, "%s", in); puts(b); }"""),
("s03_vector_sum", """
long sum(const vector<int>& v) { long s = 0; for (size_t i = 0; i < v.size(); ++i) s += v[i]; return s; }
int main() { vector<int> v{1,2,3}; cout << sum(v); }"""),
("s04_raii", """
#include <memory>
struct Node { int v; unique_ptr<Node> next; };
int main() { auto n = make_unique<Node>(); n->v = 3; return n->v; }"""),
("s05_checked_alloc", """
char* dup(const char* s) { size_t n = strlen(s) + 1; char* d = (char*)malloc(n); if (!d) return nullptr; memcpy(d, s, n); return d; }"""),
("s06_bounded_index", """
int get(int i) { static const int t[4] = {1,2,3,4}; if (i < 0 || i > 3) return -1; return t[i]; }"""),
("s07_getline_ok", """
int main() { string line; while (getline(cin, line)) cout << line.size() << "\\n"; }"""),
("s08_fgets_ok", """
int main() { char b[100]; while (fgets(b, sizeof b, stdin)) fputs(b, stdout); }"""),
("s09_matrix", """
int main() { int m[3][3]; for (int i = 0; i < 3; i++) for (int j = 0; j < 3; j++) m[i][j] = i * j; return m[2][2]; }"""),
("s10_const_literals", """
const char* kName = "service"; const int kMax = 32;
int main() { char b[kMax]; strcpy(b, kName); return b[0]; }"""),
("s11_file_read", """
int main() { ifstream f("data.txt"); string s; while (f >> s) cout << s; }"""),
("s12_sort", """
#include <algorithm>
int main() { vector<int> v{3,1,2}; sort(v.begin(), v.end()); for (int x : v) cout << x; }"""),
]
