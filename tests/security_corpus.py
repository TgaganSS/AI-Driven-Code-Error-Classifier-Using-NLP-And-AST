"""
Labelled corpus used to *measure* the security analyzer (recall on vulnerable
code, false positives on safe code).  Each vulnerable entry lists the CWE ids
a correct tool should report; ``needs_compiler`` marks bugs that only the
compiler's flow analysis (-O2 -W...) can see.
"""

HDR = "#include <cstdio>\n#include <cstdlib>\n#include <cstring>\n#include <iostream>\n#include <string>\n#include <vector>\n#include <unistd.h>\n#include <sys/stat.h>\nusing namespace std;\n"

# (id, expected CWE set (any one suffices), needs_compiler, body)
VULN = [
 ("gets", {242, 120}, False, "void f(){ char b[16]; gets(b); puts(b); }"),
 ("strcpy_literal_overflow", {120, 787}, False, 'void f(){ char b[8]; strcpy(b, "this string is far too long"); puts(b); }'),
 ("strcpy_unknown_src", {120, 676}, False, "void f(const char* s){ char b[8]; strcpy(b, s); puts(b); }"),
 ("cin_char_array", {120}, False, "void f(){ char b[16]; cin >> b; cout << b; }"),
 ("scanf_percent_s", {120}, False, 'void f(){ char b[16]; scanf("%s", b); puts(b); }'),
 ("sprintf_argv", {120, 787}, False, 'int main(int argc, char** argv){ char b[32]; sprintf(b, "hi %s", argv[1]); puts(b); return 0; }'),
 ("printf_argv", {134}, False, "int main(int argc, char** argv){ printf(argv[1]); return 0; }"),
 ("printf_param", {134}, False, "void f(char* user){ printf(user); }"),
 ("system_argv", {78}, False, "int main(int argc, char** argv){ system(argv[1]); return 0; }"),
 ("system_cstr", {78}, False, 'void f(string in){ string c = "ls " + in; system(c.c_str()); }'),
 ("popen_cin", {78}, False, 'void f(){ string n; cin >> n; string c = "cat " + n; FILE* p = popen(c.c_str(), "r"); pclose(p); }'),
 ("memcpy_overflow", {787, 120}, False, "void f(const char* s){ char b[16]; memcpy(b, s, 64); puts(b); }"),
 ("memcpy_tainted_len", {119, 129}, False, "void f(const char* s){ char b[16]; int n; cin >> n; memcpy(b, s, n); puts(b); }"),
 ("index_literal_oob", {787, 125}, False, "void f(){ int a[10]; a[10] = 1; }"),
 ("index_tainted", {129, 787}, False, "void f(){ int a[10]; int i; cin >> i; a[i] = 1; }"),
 ("offbyone_loop", {193, 787}, False, "void f(){ int a[10]; for (int i = 0; i <= 10; i++) a[i] = 0; }"),
 ("malloc_unchecked", {476}, False, "void f(){ char* p = (char*)malloc(10); p[0] = 'a'; free(p); }"),
 ("leak_malloc", {401}, False, "void f(){ char* p = (char*)malloc(10); if (p) p[0] = 'a'; }"),
 ("leak_new", {401}, False, "void f(){ int* p = new int[10]; p[0] = 1; }"),
 ("new_array_delete", {762}, False, "void f(){ int* p = new int[10]; delete p; }"),
 ("malloc_delete", {762}, False, "void f(){ int* p = (int*)malloc(4); if (p) { delete p; } }"),
 ("double_free", {415}, False, "void f(){ char* p = (char*)malloc(4); if (!p) return; free(p); free(p); }"),
 ("double_delete", {415}, False, "void f(){ int* p = new int(1); delete p; delete p; }"),
 ("uaf_free", {416}, False, "void f(){ char* p = (char*)malloc(4); if (!p) return; free(p); p[0] = 'x'; }"),
 ("uaf_delete", {416}, False, "void f(){ int* p = new int(1); delete p; *p = 2; }"),
 ("alloc_overflow", {190, 789}, False, "void f(){ size_t n, m; cin >> n >> m; char* p = (char*)malloc(n * m); if (p) free(p); }"),
 ("strlen_offbyone", {131, 193}, False, "char* f(const char* s){ char* d = (char*)malloc(strlen(s)); if (!d) return 0; strcpy(d, s); return d; }"),
 ("hardcoded_password", {798}, False, 'bool f(const string& in){ string password = "hunter2hunter2"; return in == password; }'),
 ("aws_key", {798}, False, 'const char* k = "AKIAIOSFODNN7EXAMPLE";'),
 ("md5", {327}, False, "void f(const char* d){ unsigned char o[16]; MD5((const unsigned char*)d, strlen(d), o); }"),
 ("rand_token", {338}, False, "int makeToken(){ return rand(); }"),
 ("srand_time_token", {337, 338}, False, "int sessionKey(){ srand(time(0)); return rand(); }"),
 ("tmpnam", {377}, False, "void f(){ char n[L_tmpnam]; tmpnam(n); }"),
 ("chmod_777", {732}, False, 'void f(){ chmod("/tmp/x", 0777); }'),
 ("path_traversal", {22}, False, 'int main(int argc, char** argv){ FILE* f = fopen(argv[1], "r"); if (f) fclose(f); return 0; }'),
 ("atoi_argv", {20, 190}, False, "int main(int argc, char** argv){ return atoi(argv[1]); }"),
 ("div_by_user", {369}, False, "int f(int a){ int d; cin >> d; return a / d; }"),
 ("strncpy_no_nul", {170}, False, 'void f(const char* s){ char b[8]; strncpy(b, s, sizeof(b)); puts(b); }'),
 ("alloca_tainted", {770}, False, "void f(){ size_t n; cin >> n; char* p = (char*)alloca(n); p[0] = 0; }"),
 ("vla_tainted", {770}, False, "void f(){ int n; cin >> n; char b[n]; b[0] = 0; }"),
 ("getenv_strcpy", {120}, False, 'void f(){ char b[16]; const char* h = getenv("HOME"); strcpy(b, h); puts(b); }'),
 ("sizeof_ptr_memset", {467}, False, "void f(char* p){ memset(p, 0, sizeof(p)); }"),
 ("fgets_too_big", {787, 120}, False, "void f(){ char b[8]; fgets(b, 64, stdin); puts(b); }"),
 ("read_too_big", {787, 120}, False, "void f(){ char b[8]; read(0, b, 100); }"),
 ("strcat_loop", {120}, False, "void f(const char* s){ char b[16] = \"\"; strcat(b, s); strcat(b, s); puts(b); }"),
 ("vector_index_tainted", {129, 787}, False, "void f(){ vector<int> v(10); int i; cin >> i; v[i] = 3; }"),
 ("umask0", {732}, False, "void f(){ umask(0); }"),
 ("tainted_sizeof_alloc", {789, 770, 190}, False, "void f(){ size_t n; cin >> n; char* p = (char*)malloc(n); if (p) free(p); }"),
 # compiler-flow only
 ("return_local_addr", {562, 825}, True, "int* f(){ int x = 5; return &x; }"),
 ("null_deref", {476}, True, "int f(){ int* p = nullptr; return *p; }"),
 ("maybe_uninit", {457}, True, "int f(int c){ int v; if (c) v = 1; return v; }"),
 ("fortified_strcpy", {120, 787, 119}, True, 'void f(){ char b[8]; strcpy(b, "overflowing literal!"); puts(b); }'),
 ("sign_compare_len", {195, 196, 197}, True, "bool f(int len, unsigned n){ return len < n; }"),
 ("unchecked_scanf", {252}, True, 'int f(){ int x; scanf("%d", &x); return x; }'),
 ("array_bounds_o2", {119, 125, 787}, True, "int f(){ int a[4]; for (int i = 0; i < 6; ++i) a[i] = i; return a[5]; }"),
 ("div_zero_literal", {369}, True, "int f(){ return 10 / 0; }"),
]

# (id, body) - must produce ZERO findings
SAFE = [
 ("strcpy_fits", 'void f(){ char b[16]; strcpy(b, "hello"); puts(b); }'),
 ("snprintf", 'void f(int x){ char b[32]; snprintf(b, sizeof b, "%d", x); puts(b); }'),
 ("std_string", "string f(const string& a, const string& b){ return a + b; }"),
 ("malloc_checked_freed", "void f(){ char* p = (char*)malloc(10); if (!p) return; p[0] = 'a'; free(p); }"),
 ("new_delete_pair", "void f(){ int* p = new int(3); *p = 4; delete p; }"),
 ("new_array_delete_array", "void f(){ int* p = new int[4]; p[0] = 1; delete[] p; }"),
 ("unique_ptr", "#include <memory>\nvoid f(){ auto p = std::make_unique<int>(3); *p = 4; }"),
 ("vector_at", "int f(const vector<int>& v){ return v.at(0); }"),
 ("validated_index", "void f(){ int a[10]; int i; cin >> i; if (i < 0 || i >= 10) return; a[i] = 1; }"),
 ("fgets_sizeof", "void f(){ char b[64]; if (fgets(b, sizeof b, stdin)) puts(b); }"),
 ("printf_literal_fmt", 'void f(const char* s){ printf("%s\\n", s); }'),
 ("getline_string", "void f(){ string s; getline(cin, s); cout << s; }"),
 ("loop_lt", "void f(){ int a[10]; for (int i = 0; i < 10; i++) a[i] = 0; }"),
 ("memcpy_sizeof", "void f(const char* s){ char b[16]; memcpy(b, s, sizeof(b)); }"),
 ("const_index_ok", "void f(){ int a[10]; a[9] = 1; a[0] = 2; }"),
 ("random_device_ok", "#include <random>\nunsigned f(){ std::random_device rd; return rd(); }"),
 ("dangerous_words_in_comments", '// strcpy(a,b); system("x"); gets(buf); password = "abc123"\nconst char* msg = "call system(x) then gets(y)";\nvoid f(){}'),
 ("password_from_env", 'string f(){ const char* e = getenv("DB_PASS"); string password = e ? e : ""; return password; }'),
 ("label_text", 'const char* passwordPrompt = "Enter your password:";'),
 ("returns_malloc", "char* f(){ char* p = (char*)malloc(10); if (!p) return nullptr; p[0] = 0; return p; }"),
 ("stores_in_struct", "struct S{ char* d; };\nvoid f(S* s){ char* p = (char*)malloc(8); s->d = p; }"),
 ("free_after_check", "void f(){ int* p = (int*)malloc(4); if (p) { *p = 1; free(p); } }"),
 ("scanf_int", 'int f(){ int n; if (scanf("%d", &n) != 1) return 0; return n; }'),
 ("strncpy_terminated", "void f(const char* s){ char b[8]; strncpy(b, s, sizeof b - 1); b[7] = 0; puts(b); }"),
 ("pointer_to_local", "void f(){ int x = 1; int* p = &x; *p = 2; }"),
 ("cp_template", "int main(){ int n; scanf(\"%d\", &n); vector<int> v(n); for (int i = 0; i < n; i++) scanf(\"%d\", &v[i]); long long s = 0; for (int x : v) s += x; printf(\"%lld\\n\", s); return 0; }"),
 ("atoi_literal", 'int f(){ return atoi("42"); }'),
 ("printf_int", 'void f(int n){ printf("%d\\n", n); }'),
 ("macro_consts", "#define N 16\nvoid f(){ char b[N]; strcpy(b, \"short\"); puts(b); b[N-1] = 0; }"),
 ("constexpr_size", "constexpr int K = 4 * 4;\nvoid f(){ int a[K]; a[15] = 1; }"),
]


def source_of(body: str) -> str:
    return HDR + body + "\n"
