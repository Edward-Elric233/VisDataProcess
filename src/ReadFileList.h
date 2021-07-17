//
// Created by edward on 2021/4/23.
//

#ifndef DATA_PROCESS_READFILELIST_H
#define DATA_PROCESS_READFILELIST_H

#include <string>
#include <vector>


class ReadFileList {
public:
    ReadFileList(const std::string &_base_path):base_path(_base_path) {}
    std::vector<std::string> operator() (std::string basepath = "");

private:
    const std::string base_path;
};


#endif //DATA_PROCESS_READFILELIST_H
