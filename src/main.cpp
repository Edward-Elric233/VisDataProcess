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
    for (auto file : file_list) {
        cout << "[DEAL FILE] " << file << endl;
        vis_lib::add_coor("../VisData/std_data/", "../VisData/drgraph_data/" ,file);
    }
    return 0;
}
