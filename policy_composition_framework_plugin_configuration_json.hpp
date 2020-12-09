#ifndef IRODS_POLICY_COMPOSITION_FRAMEWORK_PLUGIN_CONFIGURATION_JSON
#define IRODS_POLICY_COMPOSITION_FRAMEWORK_PLUGIN_CONFIGURATION_JSON

#include <string>
#include <vector>

#include "rcMisc.h"
#include "irods_get_full_path_for_config_file.hpp"
#include "irods_server_properties.hpp"

#include "json.hpp"

namespace irods {
    struct plugin_configuration_json {
        using json = nlohmann::json;

        json plugin_configuration;

        const std::string instance_name;

        explicit plugin_configuration_json(
            const std::string& _instance_name ) :
            instance_name{_instance_name} {
            try {
                std::string cfg_file{};
                error ret = get_full_path_for_config_file(SERVER_CONFIG_FILE, cfg_file);
                if(!ret.ok()) {
                    rodsLog(LOG_NOTICE, "get_full_path_for_config_file failed for server_config");
                    return;
                }

                rodsLog(LOG_DEBUG, "[%s] Loading [%s]", _instance_name.c_str(), cfg_file.c_str());

                std::ifstream ifn(cfg_file.c_str());
                if(!ifn.is_open()) {
                    rodsLog(LOG_ERROR, "[%s] failed to open [%s]", _instance_name.c_str(), cfg_file.c_str());
                    return;
                }

                json server_config;
                server_config = json::parse(ifn);
                ifn.close();

                if(server_config.empty()) {
                    rodsLog(LOG_ERROR, "[%s] empty server config json object", _instance_name.c_str());
                    return;
                }

                auto reps = server_config["plugin_configuration"]["rule_engines"];
                if(reps.empty()) {
                    rodsLog(LOG_ERROR, "[%s] empty rule engine plugin json array", _instance_name.c_str());
                    return;
                }

                for(auto& rep : reps) {
                    if(rep["instance_name"] == _instance_name) {
                        plugin_configuration = rep["plugin_specific_configuration"];
                        break;
                    }
                }
            }
            catch(const json::exception& e) {
                rodsLog(LOG_ERROR, "[%s] Exception Caught parsing JSON configuration [%s]", _instance_name.c_str(), e.what());
            }

        } // ctor plugin_configuration_json

    }; // struct plugin_configuration

} // namespace irods

#endif // IRODS_POLICY_COMPOSITION_FRAMEWORK_PLUGIN_CONFIGURATION_JSON
