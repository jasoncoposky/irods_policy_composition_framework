
#include "policy_engine_configuration.hpp"
#include "irods_server_properties.hpp"

namespace irods {
    policy_engine_configuration::policy_engine_configuration(
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

                    if(plugin_spec_cfg.find(example_metadata_attribute_configuration) != plugin_spec_cfg.end()) {
                        example_metadata_attribute = boost::any_cast<std::string>(
                                                         plugin_spec_cfg.at(
                                                         example_metadata_attribute_configuration));
                    }

                    if(plugin_spec_cfg.find(example_key_configuration) != plugin_spec_cfg.end()) {
                         example_value_configuration = boost::any_cast<std::string>(
                                                           plugin_spec_cfg.at(example_key_configuration));
                    }

                    if(plugin_spec_cfg.find("example_integer_default_configuration") != plugin_spec_cfg.end()) {
                        example_integer_default_configuration = boost::any_cast<int>(
                                                                    plugin_spec_cfg.at(
                                                                    "example_integer_default_configuration"));
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
    } // ctor policy_engine_configuration

} // namepsace irods

