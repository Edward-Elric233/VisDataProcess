// Copyright(C), Edward-Elric233
// Author: Edward-Elric233
// Version: 1.0
// Date: 2021/7/14
// Description: test for read json data
#include "json.hpp"
#include <iostream>
#include <fstream>

using namespace std;
using nlohmann::json;

int main() {
    ios::sync_with_stdio(false);
    ifstream is("../ISData/data1.json");
    json j;
    is >> j;
    cout << j.dump(4);
    return 0;
}
