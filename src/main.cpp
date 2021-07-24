#include <iostream>
#include <string>
#include <vector>
#include "ReadFileList.h"
#include "data_process.h"

using namespace std;

int main() {
    ios::sync_with_stdio(false);
//    ReadFileList readFileList("../ISData");
//    auto file_list = readFileList();
//
//    for (auto file : file_list) {
//        information_security::works("../ISData/", "../ISOutput/", file);
//    }
    information_security::dot2graph_deal("../ISOutput/dot/data2.json", "../ISOutput/graph/data2.json");

    return 0;
}
