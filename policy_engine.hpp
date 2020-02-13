#ifndef POLICY_ENGINE_HPP
#define POLICY_ENGINE_HPP

#include "irods_re_plugin.hpp"
#include "irods_re_ruleexistshelper.hpp"
#include "rcMisc.h"
#include <boost/any.hpp>
#include "utilities.hpp"

#include "json.hpp"

namespace irods {

    namespace policy_engine {

        using json = nlohmann::json;

        struct context {
            ruleExecInfo_t* rei{};
            std::string     usage_text{};
            std::string     instance_name{};
            std::string     policy_name{};
            std::string     policy_usage{};
            json            parameters{};
            json            configuration{};
        }; // struct context

        using arg_type            = std::reference_wrapper<std::string>;
        using plugin_type         = pluggable_rule_engine<irods::default_re_ctx>;
        using plugin_pointer_type = plugin_type*;
        using implementation_type = std::function<error(const context&)>;

        context             policy_context;
        implementation_type policy_implementation;

        namespace {
            error start(
                  default_re_ctx&
                , const std::string&)
            {
                RuleExistsHelper::Instance()->registerRuleRegex(
                    policy_context.policy_name + ".*");
                return SUCCESS();
            }

            error stop(
                default_re_ctx&,
                const std::string& ) {
                return SUCCESS();
            }

            auto rule_name_is_supported(const std::string& _rule_name)
            {
                return (policy_context.policy_name  == _rule_name ||
                        policy_context.policy_usage == _rule_name);
            } // rule_name_is_supported

            error rule_exists(
                  default_re_ctx&
                , const std::string& _rule_name
                , bool&              _return_value)
            {
                _return_value = rule_name_is_supported(_rule_name);
                return SUCCESS();
            }

            error list_rules(
                 default_re_ctx&
                , std::vector<std::string>& _rules)
            {
                _rules.push_back(policy_context.policy_name);
                _rules.push_back(policy_context.policy_usage);
                return SUCCESS();
            }

            bool get_log_errors_flag(
                  const json& _params
                , const json& _config)
            {
                bool flag = false;
                if(!_params.empty()) {
                    flag = (_params.find("log_errors") !=
                            _params.end());
                }

                if(!flag && !_config.empty()) {
                    flag = (_config.find("log_errors") !=
                            _config.end());
                }

                return flag;

            } // get_log_errors_flag

            error exec_rule(
                default_re_ctx&
                , const std::string&     _rule_name
                , std::list<boost::any>& _arguments
                , callback               _eff_hdlr)
            {

                ruleExecInfo_t* rei{};
                const auto err = _eff_hdlr("unsafe_ms_ctx", &rei);
                if(!err.ok()) {
                    return ERROR(SYS_NOT_SUPPORTED, err.result());
                }

                bool log_errors = false;

                try {
                    if(policy_context.policy_usage == _rule_name) {
                        auto it = _arguments.begin();
                        auto parameter_string{ boost::any_cast<arg_type>(*it) }; ++it;

                        parameter_string.get() = policy_context.usage_text;

                        return SUCCESS();
                    }
                    else if(policy_context.policy_name == _rule_name) {
                        policy_context.rei = rei;

                        auto it = _arguments.begin();
                        auto parameter_string{ boost::any_cast<arg_type>(*it) }; ++it;
                        auto configuration_string{ boost::any_cast<arg_type>(*it) };

                        bool log_errors = false;

                        if(!parameter_string.get().empty()) {
                            policy_context.parameters = json::parse(parameter_string.get());
                        }

                        if(!configuration_string.get().empty()) {
                            policy_context.configuration = json::parse(configuration_string.get());
                        }

                        log_errors = get_log_errors_flag(
                                           policy_context.parameters
                                         , policy_context.configuration);

                        auto err = policy_implementation(policy_context);

                        if(!err.ok()) {
                            if(log_errors) { irods::log(err); }
                            THROW(err.code(), err.result());
                        }
                    }

                }
                catch(const std::invalid_argument& _e) {
                    if(log_errors) { irods::log(err); }
                    exception_to_rerror(
                        SYS_NOT_SUPPORTED,
                        _e.what(),
                        rei->rsComm->rError);
                    return ERROR(
                               SYS_NOT_SUPPORTED,
                               _e.what());
                }
                catch(const boost::bad_any_cast& _e) {
                    if(log_errors) { irods::log(err); }
                    exception_to_rerror(
                        SYS_NOT_SUPPORTED,
                        _e.what(),
                        rei->rsComm->rError);
                    return ERROR(
                               SYS_NOT_SUPPORTED,
                               _e.what());
                }
                catch(const exception& _e) {
                    if(log_errors) { irods::log(err); }
                    exception_to_rerror(
                        _e,
                        rei->rsComm->rError);
                    return ERROR(
                               SYS_NOT_SUPPORTED,
                               _e.what());
                }
                catch(...) {
                    rodsLog(LOG_ERROR, "policy_engine :: an unknown error has occurred.");
                    return ERROR(
                               SYS_NOT_SUPPORTED,
                               "policy_engine :: an unknown error has occurred.");
                }


                // given that this is a specific policy implementation which does not react
                // to policy enforcement points we can return SUCCESS() rather than
                // CODE(RULE_ENGINE_CONTINUE), as there should only be one policy engine configured
                return SUCCESS();

            } // exec_rule

            error exec_rule_text(
                  default_re_ctx&
                , const std::string&
                , msParamArray_t*
                , const std::string&
                , callback )
            {
                return ERROR(
                        RULE_ENGINE_CONTINUE,
                        "exec_rule_text is not supported");
            } // exec_rule_text

            error exec_rule_expression(
                  default_re_ctx&
                , const std::string&
                , msParamArray_t*
                , callback)
            {
                return ERROR(
                        RULE_ENGINE_CONTINUE,
                        "exec_rule_expression is not supported");
            } // exec_rule_expression

        } // namespace

        plugin_pointer_type make(
                const std::string&  _plugin_name
              , const std::string&  _policy_name
              , const std::string&  _usage_text
              , implementation_type _policy_implementation)
        {

            policy_implementation        = _policy_implementation;
            policy_context.usage_text    = _usage_text;
            policy_context.policy_name   = _policy_name;
            policy_context.policy_usage  = _policy_name + "_usage";
            policy_context.instance_name = _plugin_name;

            auto rule_engine_plugin = new plugin_type(policy_context.instance_name, "");

            rule_engine_plugin->add_operation<
                irods::default_re_ctx&,
                const std::string&>(
                    "start",
                    std::function<
                        irods::error(
                            irods::default_re_ctx&,
                            const std::string&)>(start));

            rule_engine_plugin->add_operation<
                irods::default_re_ctx&,
                const std::string&>(
                    "stop",
                    std::function<
                        irods::error(
                            irods::default_re_ctx&,
                            const std::string&)>(stop));

            rule_engine_plugin->add_operation<
                irods::default_re_ctx&,
                const std::string&,
                bool&>(
                    "rule_exists",
                    std::function<
                        irods::error(
                            irods::default_re_ctx&,
                            const std::string&,
                            bool&)>(rule_exists));

            rule_engine_plugin->add_operation<
                irods::default_re_ctx&,
                std::vector<std::string>&>(
                    "list_rules",
                    std::function<
                        irods::error(
                            irods::default_re_ctx&,
                            std::vector<std::string>&)>(list_rules));

            rule_engine_plugin->add_operation<
                irods::default_re_ctx&,
                const std::string&,
                std::list<boost::any>&,
                irods::callback>(
                    "exec_rule",
                    std::function<
                        irods::error(
                            irods::default_re_ctx&,
                            const std::string&,
                            std::list<boost::any>&,
                            irods::callback)>(exec_rule));

            rule_engine_plugin->add_operation<
                irods::default_re_ctx&,
                const std::string&,
                msParamArray_t*,
                const std::string&,
                irods::callback>(
                    "exec_rule_text",
                    std::function<
                        irods::error(
                            irods::default_re_ctx&,
                            const std::string&,
                            msParamArray_t*,
                            const std::string&,
                            irods::callback)>(exec_rule_text));

            rule_engine_plugin->add_operation<
                irods::default_re_ctx&,
                const std::string&,
                msParamArray_t*,
                irods::callback>(
                    "exec_rule_expression",
                    std::function<
                        irods::error(
                            irods::default_re_ctx&,
                            const std::string&,
                            msParamArray_t*,
                            irods::callback)>(exec_rule_expression));

            return rule_engine_plugin;

        } // make

    }; // namespace policy_engine

} // namespace irods

#endif // POLICY_ENGINE_HPP
