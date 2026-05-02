#include "flat_rt.h"
#include <iostream>
#include <arpa/inet.h>

using namespace flatrt;

uint32_t ip4(const char* s) {
    uint32_t x;
    inet_pton(AF_INET, s, &x);
    return x;
}

int main() {
    FlatRT rt(32);

    int nh1=1, nh2=2, nh3=3;

    uint32_t a = ip4("10.0.0.0");
    uint32_t b = ip4("10.1.0.0");
    uint32_t c = ip4("10.1.1.0");
    uint32_t t = ip4("10.1.1.5");

    rt.update_insert((uint8_t*)&a, 8, &nh1);
    rt.update_insert((uint8_t*)&b, 16, &nh2);
    rt.update_insert((uint8_t*)&c, 24, &nh3);

    std::cout << "LPM = " << *(int*)rt.lookup((uint8_t*)&t) << "\n";

    auto r = rt.update_delete((uint8_t*)&c, 24);

    std::cout << "After delete = "
              << *(int*)rt.lookup((uint8_t*)&t) << "\n";

    // cleanup
    for (auto t : r.tbl16s) delete t;

    return 0;
}