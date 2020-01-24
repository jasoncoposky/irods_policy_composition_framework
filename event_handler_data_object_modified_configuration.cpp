
#include "event_handler_data_object_modified_configuration.hpp"
#include "irods_server_properties.hpp"
#include "irods_get_full_path_for_config_file.hpp"

#include <fstream>

namespace irods {
    event_handler_data_object_modified_configuration::event_handler_data_object_modified_configuration(
        const std::string& _instance_name ) :
        instance_name{_instance_name} {
        try {
            std::string cfg_file{};
            error ret = get_full_path_for_config_file(SERVER_CONFIG_FILE, cfg_file);
            if(!ret.ok()) {
                rodsLog(LOG_NOTICE, "get_full_path_for_config_file failed for server_config");
                return;
            }
            rodsLog(LOG_DEBUG, "Loading [%s]", cfg_file.c_str());

            std::ifstream ifn(cfg_file.c_str());
            if(!ifn.is_open()) {
                rodsLog(LOG_NOTICE, "failed to open [%s]", cfg_file.c_str());
                return;
            }

            json server_config;
            server_config = json::parse(ifn);
            //server_config << ifn;
            ifn.close();

            if(server_config.empty()) {
                std::cout << "SERVER_CONFIG IS EMPTY\n";
                return;
            }

            auto reps = server_config["plugin_configuration"]["rule_engines"];
            if(reps.empty()) {
                std::cout << "REPS ARE EMPTY\n";
                return;
            }

            for(auto& rep : reps) {
                if(rep["instance_name"] == _instance_name) {
                    policies_to_invoke_configuration = rep["plugin_specific_configuration"]["policies_to_invoke"];
                }
            }
        }
        catch(...) {
            rodsLog(LOG_ERROR, "[%s] Exceptio Caught parsing JSON configuration", __FUNCTION__);
        }
    } // ctor event_handler_data_object_modified_configuration

} // namepsace irods

