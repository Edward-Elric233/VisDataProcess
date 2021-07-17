//
// Created by edward on 2021/4/23.
//

#include "ReadFileList.h"
#include <dirent.h>
#include <unistd.h>
#include <cstring>

using namespace std;

std::vector<std::string> ReadFileList::operator()(std::string basepath) {
    if (basepath.empty()) {
        basepath = base_path;
    }
    vector<string> file_list;

    DIR *dir;
    struct dirent *ptr;
    char base[1000];

    if ((dir=opendir(basepath.c_str())) == NULL)
    {
        perror("Open dir error...");
        exit(1);
    }

    while ((ptr=readdir(dir)) != NULL)
    {
        if(strcmp(ptr->d_name,".")==0 || strcmp(ptr->d_name,"..")==0)    ///current dir OR parrent dir
            continue;
        else if(ptr->d_type == 8) {    ///file
            //printf("d_name:%s/%s\n",basePath,ptr->d_name);
            file_list.emplace_back(ptr->d_name);
        } else if(ptr->d_type == 10) {    ///link file
            //printf("d_name:%s/%s\n",basePath,ptr->d_name);
        } else if(ptr->d_type == 4) {     ///dir
//            memset(base,'\0',sizeof(base));
//            strcpy(base,basePath);
//            strcat(base,"/");
//            strcat(base,ptr->d_name);
//            readFileList(base);
        }
    }
    closedir(dir);
    return std::move(file_list);
}