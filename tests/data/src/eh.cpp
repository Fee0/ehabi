// C++ exception handling fixture.
// Compile with: clang++ --target=armv7a-linux-gnueabihf -O1 -fPIC -c eh.cpp
// (add -DNS=thumb for a second copy built with --target=thumbv7a-...)
#ifdef NS
namespace NS {
#endif
struct Guard {
    int *p;
    ~Guard() { *p += 1; }
};

void may_throw(int);
void sink(int);

int catch_int(int x) {
    try {
        may_throw(x);
    } catch (int &e) {
        return e;
    } catch (...) {
        return -1;
    }
    return 0;
}

void cleanup_only(int *counter) {
    Guard g{counter};
    may_throw(*counter);
    sink(*counter);
}

void no_throw(int x) noexcept {
    may_throw(x);
}

void rethrow(int x) {
    try {
        may_throw(x);
    } catch (...) {
        sink(x);
        throw;
    }
}

double leaf(double a, double b) { return a * b + 1.0; }

void big_frame(int x) {
    volatile char buf[1024];
    buf[x] = 1;
    may_throw(buf[x + 1]);
}

#ifdef NS
}
#endif
