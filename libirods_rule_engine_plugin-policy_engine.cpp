
#include "irods_re_plugin.hpp"
#include "irods_re_ruleexistshelper.hpp"
#include "utilities.hpp"
#include "policy_engine_configuration.hpp"
#include "rcMisc.h"

#include <boost/any.hpp>

namespace {
    std::unique_ptr<irods::policy_engine_configuration> config;
    std::string plugin_instance_name{};

    const std::string IMPLEMENTED_POLICY_NAME{"irods_policy_engine_example"};

    auto rule_name_is_supported(const std::string& _rule_name) {
        return (IMPLEMENTED_POLICY_NAME == _rule_name);
    } // rule_name_is_supported

    void apply_example_policy(
        rsComm_t*          _comm,
        const std::string& _instance_name,
        const std::string& _operation_name,
        const std::string& _json_string) {
        rodsLog(
            LOG_NOTICE,
            "[%s]::[%s] operation [%s] parameters [%s]",
            _instance_name.c_str(),
            IMPLEMENTED_POLICY_NAME.c_str(),
            _operation_name.c_str(),
            _json_string.c_str());
    } // apply_example_policy

} // namespace

irods::error start(
    irods::default_re_ctx&,
    const std::string& _instance_name ) {
    // capture plugin instance name
    plugin_instance_name = _instance_name;

    // load the plugin specific configuration for this instance
    config = std::make_unique<irods::policy_engine_configuration>(plugin_instance_name);

    // register the policy implementation name as supported by this plugin
    RuleExistsHelper::Instance()->registerRuleRegex(IMPLEMENTED_POLICY_NAME);

    return SUCCESS();
}

irods::error stop(
    irods::default_re_ctx&,
    const std::string& ) {
    return SUCCESS();
}

irods::error rule_exists(
    irods::default_re_ctx&,
    const std::string& _rule_name,
    bool&              _return_value) {
    _return_value = rule_name_is_supported(_rule_name);
    return SUCCESS();
}

irods::error list_rules(
    irods::default_re_ctx&,
    std::vector<std::string>& _rules) {
    _rules.push_back(IMPLEMENTED_POLICY_NAME);
    return SUCCESS();
}

irods::error exec_rule(
    irods::default_re_ctx&,
    const std::string&     _rule_name,
    std::list<boost::any>& _arguments,
    irods::callback        _eff_hdlr) {
    ruleExecInfo_t* rei{};

    // capture an rei which provides the rsComm_t structure and rError
    const auto err = _eff_hdlr("unsafe_ms_ctx", &rei);
    if(!err.ok()) {
        // always return SYS_NOT_SUPPORTED given an error in a Policy Engine
        // which allows the REPF to continue trying other plugins or rule bases
        return ERROR(SYS_NOT_SUPPORTED, err.result());
    }

    try {
        if(IMPLEMENTED_POLICY_NAME == _rule_name) {
            // walk the arguments list and any_cast them to known types given this policy signature
            auto it = _arguments.begin();
            std::string instance_name{ boost::any_cast<std::string>(*it) }; ++it;
            std::string operation_name{ boost::any_cast<std::string>(*it) }; ++it;
            std::string json_string{ boost::any_cast<std::string>(*it) };

            // invoke example policy given our arguments
            apply_example_policy(
                rei->rsComm,
                instance_name,
                operation_name,
                json_string);
        }

        return ERROR(
                   SYS_NOT_SUPPORTED,
                   _rule_name);
    }
    catch(const std::invalid_argument& _e) {
        // pass the exception to the rError stack to get the result
        // back to the client for forensics
        irods::exception_to_rerror(
            SYS_NOT_SUPPORTED,
            _e.what(),
            rei->rsComm->rError);
        return ERROR(
                   SYS_NOT_SUPPORTED,
                   _e.what());
    }
    catch(const boost::bad_any_cast& _e) {
        irods::exception_to_rerror(
            SYS_NOT_SUPPORTED,
            _e.what(),
            rei->rsComm->rError);
        return ERROR(
                   SYS_NOT_SUPPORTED,
                   _e.what());
    }
    catch(const irods::exception& _e) {
        irods::exception_to_rerror(
            _e,
            rei->rsComm->rError);
        return ERROR(
                   SYS_NOT_SUPPORTED,
                   _e.what());
    }

    // given that this is a specific policy implementation which does not react
    // to policy enforcement points we can return SUCCESS() rather than
    // CODE(RULE_ENGINE_CONTINUE), as there should only be one policy engine configured
    return SUCCESS();

} // exec_rule

irods::error exec_rule_text(
    irods::default_re_ctx&,
    const std::string&,
    msParamArray_t*,
    const std::string&,
    irods::callback ) {
    return ERROR(
            RULE_ENGINE_CONTINUE,
            "exec_rule_text is not supported");
} // exec_rule_text

irods::error exec_rule_expression(
    irods::default_re_ctx&,
    const std::string&,
    msParamArray_t*,
    irods::callback) {
    return ERROR(
            RULE_ENGINE_CONTINUE,
            "exec_rule_expression is not supported");
} // exec_rule_expression

extern "C"
irods::pluggable_rule_engine<irods::default_re_ctx>* plugin_factory(
    const std::string& _inst_name,
    const std::string& _context ) {
    irods::pluggable_rule_engine<irods::default_re_ctx>* re =
        new irods::pluggable_rule_engine<irods::default_re_ctx>(
                _inst_name,
                _context);

    re->add_operation<
        irods::default_re_ctx&,
        const std::string&>(
            "start",
            std::function<
                irods::error(
                    irods::default_re_ctx&,
                    const std::string&)>(start));

    re->add_operation<
        irods::default_re_ctx&,
        const std::string&>(
            "stop",
            std::function<
                irods::error(
                    irods::default_re_ctx&,
                    const std::string&)>(stop));

    re->add_operation<
        irods::default_re_ctx&,
        const std::string&,
        bool&>(
            "rule_exists",
            std::function<
                irods::error(
                    irods::default_re_ctx&,
                    const std::string&,
                    bool&)>(rule_exists));

    re->add_operation<
        irods::default_re_ctx&,
        std::vector<std::string>&>(
            "list_rules",
            std::function<
                irods::error(
                    irods::default_re_ctx&,
                    std::vector<std::string>&)>(list_rules));

    re->add_operation<
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

    re->add_operation<
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

    re->add_operation<
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
    return re;

} // plugin_factory




