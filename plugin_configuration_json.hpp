#ifndef PLUGIN_CONFIGURATION_JSON
#define PLUGIN_CONFIGURATION_JSON

#include <string>
#include <vector>
#include "rcMisc.h"

#include "json.hpp"

namespace irods {
    struct plugin_configuration_json {
        using json = nlohmann::json;
        json plugin_configuration;
        const std::string instance_name;
        explicit plugin_configuration_json(const std::string&);
    };
} // namespace irods

#endif // PLUGIN_CONFIGURATION_JSON
