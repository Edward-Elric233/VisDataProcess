#include <iostream>
#include <string>
#include <vector>
#include "ReadFileList.h"
#include "data_process.h"

using namespace std;

int main() {
    ios::sync_with_stdio(false);
    ReadFileList readFileList("../VisData/std_data");
    auto file_list = readFileList();

    information_security::works("../ISData/", "../ISOutput/", "data1.json");

    return 0;
}
