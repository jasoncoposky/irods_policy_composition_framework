#ifndef CONFIGURATION_MANAGER_HPP
#define CONFIGURATION_MANAGER_HPP

#include "rule_engine_plugin_configuration_json.hpp"

namespace irods::policy_engine {
    class configuration_manager {
        using json = nlohmann::json;

        public:
        configuration_manager(
              const std::string _in
            , const json&       _cj)
            :  plugin_cfg_{_in}
            ,  call_cfg_{_cj}
        {
        } // ctor

        template<typename T>
        std::tuple<error, T>
        get_value(
            const std::string& _key
          , const T&           _default)
        {
            const auto& tmp_cfg = plugin_cfg_.plugin_configuration;

            if(call_cfg_.empty() && tmp_cfg.empty() ) {
                return std::make_tuple(
                           ERROR(
                               SYS_INVALID_INPUT_PARAM,
                               "configuration is empty"),
                           _default);
            }

            if(!call_cfg_.empty()) {
                if(call_cfg_.find(_key) != call_cfg_.end()) {
                    return std::make_tuple(SUCCESS(), call_cfg_.at(_key).get<T>());
                }
            }

            if(!tmp_cfg.empty()) {
                if(tmp_cfg.find(_key) != tmp_cfg.end()) {
                    return std::make_tuple(SUCCESS(), tmp_cfg.at(_key).get<T>());
                }
            }

            return std::make_tuple(
                       ERROR(
                           SYS_INVALID_INPUT_PARAM,
                           boost::format("[%s] key not found")
                           % _key),
                       _default);
        } // get_value

        std::tuple<error, std::string>
        get_value(
            const std::string& _key
          , const char         _default[])
        {
            const auto& tmp_cfg = plugin_cfg_.plugin_configuration;

            if(call_cfg_.empty() && tmp_cfg.empty() ) {
                return std::make_tuple(
                           ERROR(
                               SYS_INVALID_INPUT_PARAM,
                               "configuration is empty"),
                           _default);
            }

            if(!call_cfg_.empty()) {
                if(call_cfg_.find(_key) != call_cfg_.end()) {
                    return std::make_tuple(SUCCESS(), call_cfg_.at(_key));
                }
            }

            if(!tmp_cfg.empty()) {
                if(tmp_cfg.find(_key) != tmp_cfg.end()) {
                    return std::make_tuple(SUCCESS(), tmp_cfg.at(_key));
                }
            }

            return std::make_tuple(
                       ERROR(
                           SYS_INVALID_INPUT_PARAM,
                           boost::format("[%s] key not found")
                           % _key),
                       _default);
        } // get_value

        private:
        plugin_configuration_json plugin_cfg_;
        const json&               call_cfg_;
    }; // class configuration_manager

} // namespace irods::policy_engine

#endif // CONFIGURATION_MANAGER_HPP