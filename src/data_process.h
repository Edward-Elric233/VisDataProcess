//
// Created by edward on 2021/4/7.
//

#ifndef DATA_PROCESS_DATA_PROCESS_H
#define DATA_PROCESS_DATA_PROCESS_H
#include <string>

namespace information_security {
/*!
 * 进行网络黑产数据处理
 */
void works(const std::string &input_filter = "data", const std::string &output_filter = "output" ,const std::string &file_name = "data1.json");

int dot2graph_deal(const std::string &input_path, const std::string &output_path);
}


    namespace vis_lib {
    /*!
    * 将以对象组织的json文件转换为以列表组织的
    * @param intput_filter
    * @param output_filter
    * @param file_name
    */
    void object2list(const std::string &input_filter = "data", const std::string &output_filter = "output" ,const std::string &file_name = "data1.json");

    /*!
     * 将原本source和target是nodes的name的数据转换成是nodes的id
     * @param intput_filter
     * @param output_filter
     * @param file_name
     */
    void str2num(const std::string &input_filter = "data", const std::string &output_filter = "output" ,const std::string &file_name = "data1.json");

    /*!
     * 将json数据转换成DRgraph算法可以处理的csv数据
     * @param input_filter
     * @param output_filter
     * @param file_name
     */
    void json2csv(const std::string &input_filter = "data", const std::string &output_filter = "output" ,const std::string &file_name = "data1.json");

    /*!
     * 将DRgraph算法处理出来的坐标添加回json数据
     * @param input_filter
     * @param output_filter
     * @param file_name
     */
    void add_coor(const std::string &input_filter = "data", const std::string &output_filter = "output" ,const std::string &file_name = "data1.json");
}

#endif //DATA_PROCESS_DATA_PROCESS_H
