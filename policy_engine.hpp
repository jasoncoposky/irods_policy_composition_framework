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
            std::string     instance_name{};
            std::string     policy_name{};
            json            parameters{};
            json            configuration{};
        }; // struct context

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
                RuleExistsHelper::Instance()->registerRuleRegex(policy_context.policy_name);
                return SUCCESS();
            }

            error stop(
                default_re_ctx&,
                const std::string& ) {
                return SUCCESS();
            }

            auto rule_name_is_supported(const std::string& _rule_name)
            {
                return (policy_context.policy_name == _rule_name);
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
                return SUCCESS();
            }

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

                try {
                    if(policy_context.policy_name == _rule_name) {
                        policy_context.rei = rei;

                        auto it = _arguments.begin();
                        std::string parameter_string{ boost::any_cast<std::string>(*it) }; ++it;
                        std::string configuration_string{ boost::any_cast<std::string>(*it) };

                        if(!parameter_string.empty()) {
                            policy_context.parameters = json::parse(parameter_string);
                        }

                        if(!configuration_string.empty()) {
                            policy_context.configuration = json::parse(configuration_string);
                        }

                        return policy_implementation(policy_context);
                    }

                }
                catch(const std::invalid_argument& _e) {
                    exception_to_rerror(
                        SYS_NOT_SUPPORTED,
                        _e.what(),
                        rei->rsComm->rError);
                    return ERROR(
                               SYS_NOT_SUPPORTED,
                               _e.what());
                }
                catch(const boost::bad_any_cast& _e) {
                    exception_to_rerror(
                        SYS_NOT_SUPPORTED,
                        _e.what(),
                        rei->rsComm->rError);
                    return ERROR(
                               SYS_NOT_SUPPORTED,
                               _e.what());
                }
                catch(const exception& _e) {
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
              , implementation_type _policy_implementation)
        {

            policy_implementation        = _policy_implementation;
            policy_context.policy_name   = _policy_name;
            policy_context.instance_name = _plugin_name;

            auto rule_engine_plugin = new plugin_type(policy_context.instance_name, {});

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
