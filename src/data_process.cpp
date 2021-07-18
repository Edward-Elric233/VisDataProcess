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

namespace information_security{

    using nlohmann::json;
    using std::string;
    using std::cout;
    using std::endl;

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


    void dot2graph_deal(const string &input_path, const string &output_path) {
        json dot_data;
        std::ifstream is(input_path);
        is >> dot_data;
        json link_data = json::array();
        json node_statistics = {
                {"Domain", 0},
                {"IP", 0},
                {"ASN", 0},
                {"IP_CIDR", 0},
                {"Cert_SHA256", 0},
                {"Whois_Name", 0},
                {"Whois_Phone", 0},
                {"Whois_Email", 0},
        };
        json link_statistics = {
                {"r_whois_name", 0},
                {"r_whois_phone", 0},
                {"r_whois_email", 0},
                {"r_cert", 0},
                {"r_certchain", 0},
                {"r_request_jump", 0},
                {"r_dns_cname", 0},
                {"r_subdomain", 0},
                {"r_dns_a", 0},
                {"r_cidr", 0},
                {"r_asn", 0},
        };
        auto deal = [&](json &node, const string &type) -> bool {
            if (!node.contains(type)) return false;
            for (auto name_ : node[type]) {
                const string &other_node_name = name_;
                const string &node_name = node["name"];
                auto iter = std::find_if(dot_data.begin(), dot_data.end(), [&](const json &x){
                    return x[NAME] == other_node_name;
                });
                if (iter == dot_data.end()) return false;
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
                link_statistics[link_type] = int(link_statistics[link_type]) + 1;
            }
            node.erase(type);
            return true;
        };
        for (auto &node : dot_data) {
            //node.erase("page");
            const string &type = node[TYPE];
            node_statistics[type] = int(node_statistics[type]) + 1;
//            if (type == "Domain") {
                deal(node, "whois_name");
                deal(node, "whois_phone");
                deal(node, "whois_email");
                deal(node, "cert");
                deal(node, "request_jump");
                deal(node, "dns_cname");
                deal(node, "subdomain");
                deal(node, "dns_a");
//            } else if (type == "Cert_SHA256") {
                deal(node, "certchain");
//            } else if (type == "IP") {
                deal(node, "asn");
                deal(node, "cidr");
//            }
        }
        std::ofstream os(output_path);
        json output_data;
        output_data["nodes"] = dot_data;
        output_data["links"] = link_data;
        //output_data["node_statistics"] = node_statistics;
        //output_data["link_statistics"] = link_statistics;
        os << output_data.dump(4);
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

void dot2graph(char *input_path, char *output_path) {
    //printf("file_name:%s\n", file_name);
    information_security::dot2graph_deal(input_path, output_path);
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