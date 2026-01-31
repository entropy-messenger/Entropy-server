#pragma once

#include <string>
#include <boost/json.hpp>

namespace entropy {

// Handles traffic normalization to mitigate side-channel attacks (e.g. packet size analysis).
class TrafficNormalizer {
public:
    static void pad_json(boost::json::object& obj, size_t target_size);
};

}
