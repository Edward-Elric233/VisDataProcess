#include "json_deal.h"
#include <fstream>
#include <json.hpp>
#include <vector>

using std::string;
using std::ifstream;
using std::ofstream;
using nlohmann::json;
using std::vector;
using std::pair;

void json2csv(const string &file_path) {
    ifstream is(file_path);
    ofstream os(file_path.substr(0, file_path.find_last_of('.')) + ".csv");
    ofstream os2(file_path.substr(0, file_path.find_last_of('.')) + ".map");
    json origin_data;
    is >> origin_data;
    json &nodes = origin_data["nodes"];
    json &links = origin_data["links"];
    os << "source,target,relation" << "\n";
    json hash_map = json::object();
    int index = 0;
    for (json &node : nodes) {
        const string node_name = node["name"];
        hash_map[node_name] = index++;
    }
    for (json &link : links) {
        const string source = link["source"];
        const string target = link["target"];
        os << hash_map[source] << "," << hash_map[target] << "," << link["relation"] << "\n";
    }
    os2 << hash_map.dump(4);
}

void csv2json(const string &file_path) {
    ifstream is_json(file_path + ".json");
    ifstream is_pos(file_path + ".pos");
    ifstream is_hash(file_path + ".map");
    json data, hash_map;
    is_json >> data;
    is_hash >> hash_map;
    is_json.close();
    ofstream os_json(file_path + ".json");
    vector<pair<double, double>> position;
    double x, y;
    while (is_pos >> x >> y) {
        position.push_back({x, y});
    }
    json &nodes = data["nodes"];
    for (json &node : nodes) {
        const string name = node["name"];
        int idx = hash_map[name];
        node["x"] = position[idx].first;
        node["y"] = position[idx].second;
    }
    os_json << data.dump(4);
}