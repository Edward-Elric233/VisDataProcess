//
// Created by edward on 2021/4/7.
//

#include "data_process.h"
#include "../lib/json.hpp"
#include <fstream>
#include <string>
#include <algorithm>
#include <iostream>
#include <unordered_map>
#include <vector>

namespace information_security{

    using nlohmann::json;
    using std::string;
    using std::cout;
    using std::endl;
    using std::vector;

    namespace {
        const string REALTION = "relation";
        const string SOURCE = "source";
        const string TARGET = "target";
        const string TYPE = "type";
        const string NAME = "name";
    }
string dot2line(string s) {
        std::replace(s.begin(), s.end(), '.', '_');
        return s;
    }

    void graph2dot_deal(const string &input_filter, const string &output_filter, const string &file_name) {
        std::ifstream is(input_filter + file_name);
        json j;
        is >> j;
        json &nodes = j["nodes"];
        json &links = j["links"];
        auto deal = [&nodes](const json &link) {
            string type = link[REALTION];
            const string &source = link[SOURCE];
            const string &target = link[TARGET];
            auto iter = std::find_if(nodes.begin(), nodes.end(), [&](const json &x){
                //cout << "[lambda]\t" << x << endl;
                return x[NAME] == source;
            });
            if (iter == nodes.end()) {
                cout << "[error]\t node not find" << endl;
            } else {
                //cout << "[deal]\t" << *iter << "\t" << source << "\t" << target << "\t" << type << endl;
            }
            //            if ((*iter)[NAME] == "hnhzjqc.com") {
            //                int i;
            //                std::cin >> i;
            //            }
            type = type.substr(2);
            if (!iter->contains(type)) {
                (*iter)[type] = json::array();
                (*iter)[type].push_back(target);
            } else {
                (*iter)[type].push_back(target);
            }
        };
        for (auto &link : links) {
            deal(link);
        }
        std::ofstream os(output_filter + file_name);
        os << nodes.dump(4);
    }

    void dfs(vector<vector<int>> &graph, int x,vector<int> &idx, int cnt) {
        idx[x] = cnt;
        for (auto v : graph[x]) {
            if (idx[v]) continue;
            dfs(graph, v, idx, cnt);
        }
    }


    int dot2graph_deal(const string &input_path, const string &output_path) {
        json dot_data;
        std::ifstream is(input_path);
        is >> dot_data;
        json link_data = json::array();
        vector<vector<int>> graph(dot_data.size());
        auto deal = [&](json &node, const string &type, int u) -> bool {
            if (!node.contains(type)) return false;
            for (auto name_ : node[type]) {
                const string &other_node_name = name_;
                const string &node_name = node["name"];
                auto iter = std::find_if(dot_data.begin(), dot_data.end(), [&](const json &x){
                    return x[NAME] == other_node_name;
                });
                if (iter == dot_data.end()) return false;
                int v = iter - dot_data.begin();
                graph[u].push_back(v);
                graph[v].push_back(u);
                const string link_type = "r_" + type;
                auto add_link = [&](const string &u, const string &v) {
                    json edge = json::object();
                    edge[SOURCE] = u;
                    edge[TARGET] = v;
                    edge[REALTION] = link_type;
                    link_data.push_back(std::move(edge));
                };
                add_link(node_name, other_node_name);
//                add_link(other_node_name, node_name);
            }
            node.erase(type);
            return true;
        };
        for (int i = 0; i < dot_data.size(); ++i) {
//        for (auto &node : dot_data) {
            json &node = dot_data[i];
            //node.erase("page");
            const string &type = node[TYPE];
//            if (type == "Domain") {
                deal(node, "whois_name", i);
                deal(node, "whois_phone", i);
                deal(node, "whois_email", i);
                deal(node, "cert", i);
                deal(node, "request_jump", i);
                deal(node, "dns_cname", i);
                deal(node, "subdomain", i);
                deal(node, "dns_a", i);
//            } else if (type == "Cert_SHA256") {
                deal(node, "certchain", i);
//            } else if (type == "IP") {
                deal(node, "asn", i);
                deal(node, "cidr", i);
//            }
        }
        int cnt = 0;
        vector<int> idx(dot_data.size(), 0);

        for (int i = 0; i < dot_data.size(); ++i) {
            if (!idx[i]) {
                ++cnt;
                dfs(graph, i, idx, cnt);
            }
        }

        vector<json> output_datas(cnt, json::object());
        for (auto &output_data : output_datas) {
            output_data["nodes"] = json::array();
            output_data["links"] = json::array();
        }

        for (int i = 0; i < dot_data.size(); ++i) {
            int data_idx = idx[i] - 1;
            output_datas[data_idx]["nodes"].push_back(dot_data[i]);
        }

        for (auto &link : link_data) {
            string name = link[SOURCE];
            auto iter = std::find_if(dot_data.begin(), dot_data.end(), [&name](const json &node) {
                return node[NAME] == name;
            });
            int data_idx = idx[iter - dot_data.begin()] - 1;
            output_datas[data_idx]["links"].push_back(link);
        }

        for (int i = 0; i < cnt; ++i) {
            string output_path_i = output_path.substr(0, output_path.find_last_of('.')) + "_" + std::to_string(i + 1) + output_path.substr(output_path.find_last_of('.'));
            std::ofstream os(output_path_i);
            os << output_datas[i].dump(4);
        }
        return cnt;
    }

    void works(const string &_input_filter, const string &_output_filter, const string &file_name) {
        graph2dot_deal(_input_filter, _output_filter + "dot/", file_name);
        dot2graph_deal(_output_filter + "dot/" + file_name, _output_filter + "graph/" + file_name);
    }

}

extern "C" {
//属于全局作用域
#include <string.h>
#include <stdio.h>

int dot2graph(char *input_path, char *output_path) {
    //printf("file_name:%s\n", file_name);
    return information_security::dot2graph_deal(input_path, output_path);
}

}

namespace vis_lib {
    using std::string;
    using nlohmann::json;
    using std::endl;
    using std::ifstream;
    using std::ofstream;
    using std::unordered_map;

    void object2list(const std::string &input_filter , const std::string &output_filter ,const std::string &file_name ) {
        ifstream is(input_filter + file_name);
        json origin_data, data;
        is >> origin_data;
        json &origin_nodes = origin_data.at("nodes");
        json &origin_links = origin_data.at("links");
        data["nodes"] = json::array();
        json &nodes = data.at("nodes");
        data["links"] = json::array();
        json &links = data.at("links");
        unordered_map<string, int> hash;
        int idx = 0;
        for (auto &item : origin_nodes.items()) {
            auto &origin_node = item.value();
            hash[origin_node["name"]] = ++idx;
            json node = json::object();
            node["id"] = idx;
            node["name"] = origin_node["name"];
            nodes.push_back(node);
        }
        for (auto &item : origin_links.items()) {
            auto &origin_link = item.value();
            json link = json::object();
//            link["source"] = hash[origin_link["source"]];
//            link["target"] = hash[origin_link["target"]];
            link["source"] = origin_link["source"];
            link["target"] = origin_link["target"];
            link["relation"] = origin_link["relation"];
            links.push_back(link);
        }
        ofstream os(output_filter + file_name);
        os << data.dump(4) << endl;
    }

    void str2num(const std::string &input_filter , const std::string &output_filter ,const std::string &file_name) {
        ifstream is(input_filter + file_name);
        ofstream os(output_filter + file_name);
        json origin_data, data;
        data["nodes"] = json::array();
        data["links"] = json::array();
        is >> origin_data;
        json &origin_nodes = origin_data["nodes"];
        json &origin_links = origin_data["links"];
        json &nodes = data["nodes"];
        json &links = data["links"];
        unordered_map<string, int> hash;

        for (auto &origin_node : origin_nodes) {
            json node = json::object();
            node["id"] = hash.size();
            node["x"] = origin_node["x"];
            node["y"] = origin_node["y"];
            hash[origin_node["name"]] = hash.size();
            nodes.push_back(node);
        }
        for (auto &origin_link : origin_links) {
            json link = json::object();
            link["relation"] = origin_link["relation"];
            link["source"] = hash[origin_link["source"]];
            link["target"] = hash[origin_link["target"]];
            links.push_back(link);
        }
        os << data.dump(4);
        is.close();
        os.close();
    }

    void json2csv(const std::string &input_filter ,const std::string &output_filter ,const std::string &file_name) {
        ifstream is(input_filter + file_name);
        ofstream os(output_filter + file_name);
        json j;
        is >> j;
        os << j["nodes"].size() << " " << j["links"].size() << "\n";
        for (auto &link : j["links"]) {
            os << link["source"] << " " << link["target"] << " 1\n";
        }
    }

    void add_coor(const std::string &input_filter ,const std::string &output_filter ,const std::string &file_name) {
        ifstream is1(input_filter + file_name);
        ifstream is2(output_filter + file_name.substr(0, file_name.find('.')) + "_out.txt");
        ofstream os(output_filter + file_name);
        json data;
        is1 >> data;
        int n, r;
        double x, y;
        is2 >> n >> r;
        r = 1000 / r;
        for (auto &node : data["nodes"]) {
            is2 >> x >> y;
            node["x"] = x * r;
            node["y"] = y * r;
        }
        os << data.dump(4);
        is1.close();
        is2.close();
        os.close();
    }
}