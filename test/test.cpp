// Copyright(C), Edward-Elric233
// Author: Edward-Elric233
// Version: 1.0
// Date: 2021/7/14
// Description: test for read json data
#include "json.hpp"
#include <iostream>
#include <fstream>
#include <set>
#include <string>

using namespace std;
using nlohmann::json;

int main() {
    ios::sync_with_stdio(false);
    ifstream is("../ISOutput/graph/data1.json");
    json j;
    is >> j;
    auto &nodes = j["nodes"];

    set<string> record;

    cout << nodes.size() << endl;

//    for (auto &node : nodes) {
//        node.erase("name");
//        node.erase("type");
//        for (auto &iter : node) {
//            cout << iter << endl;
//        }
//    }
    return 0;
}
