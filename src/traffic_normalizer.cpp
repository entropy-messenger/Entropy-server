#include "traffic_normalizer.hpp"
#include <boost/json.hpp>

namespace entropy {

void TrafficNormalizer::pad_json(boost::json::object& obj, size_t target_size) {
    std::string current = boost::json::serialize(obj);
    if (current.size() >= target_size) return;
    
    size_t needed = target_size - current.size();
    
    if (needed < 15) return; 
    
    std::string pad_str(needed - 13, ' ');
    obj["padding"] = pad_str;
}

}
