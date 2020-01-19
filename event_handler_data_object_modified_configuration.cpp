
#include "event_handler_data_object_modified_configuration.hpp"
#include "irods_server_properties.hpp"

namespace irods {
    event_handler_data_object_modified_configuration::event_handler_data_object_modified_configuration(
        const std::string& _instance_name ) :
        instance_name{_instance_name} {
        bool success_flag = false;

        try {
            const auto& rule_engines = get_server_property<
                const std::vector<boost::any>&>(
                        std::vector<std::string>{
                        CFG_PLUGIN_CONFIGURATION_KW,
                        PLUGIN_TYPE_RULE_ENGINE});
            for ( const auto& elem : rule_engines ) {
                const auto& rule_engine = boost::any_cast<const std::unordered_map<std::string, boost::any>&>(elem);
                const auto& inst_name   = boost::any_cast<const std::string&>(rule_engine.at(CFG_INSTANCE_NAME_KW));

                if ( inst_name == _instance_name && rule_engine.count(CFG_PLUGIN_SPECIFIC_CONFIGURATION_KW) > 0) {
                    const auto& plugin_spec_cfg = boost::any_cast<const std::unordered_map<std::string, boost::any>&>(
                            rule_engine.at(CFG_PLUGIN_SPECIFIC_CONFIGURATION_KW));

                    if(plugin_spec_cfg.find(policy_to_invoke_configuration) != plugin_spec_cfg.end()) {
                        using json = nlohmann::json;
                        // fetch the json array of strings which are the policy we wish to invoke
                        auto anys = plugin_spec_cfg.at(policy_to_invoke_configuration);
                        auto vals = boost::any_cast<std::vector<boost::any>>(anys);
                        for(auto& v : vals) {
                            policies_to_invoke.push_back(boost::any_cast<std::string>(v));
                        }
                    }

                    success_flag = true;
                } // if inst_name && REP Config
            } // for rule_engines
        } catch ( const boost::bad_any_cast& e ) {
            THROW( INVALID_ANY_CAST, e.what() );
        } catch ( const std::out_of_range& e ) {
            THROW( KEY_NOT_FOUND, e.what() );
        }

        if(!success_flag) {
            THROW(
                SYS_INVALID_INPUT_PARAM,
                boost::format("failed to find configuration for policy engine plugin [%s]") %
                _instance_name);
        }
    } // ctor event_handler_data_object_modified_configuration

} // namepsace irods

