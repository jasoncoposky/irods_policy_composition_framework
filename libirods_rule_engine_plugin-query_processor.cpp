
#include "irods_re_plugin.hpp"
#include "irods_re_ruleexistshelper.hpp"
#include "utilities.hpp"
#include "rcMisc.h"
#include "irods_query.hpp"
#include "thread_pool.hpp"
#include "query_processor.hpp"
#include "json.hpp"

#include <boost/any.hpp>

namespace {
    std::string plugin_instance_name{};
    const std::string IMPLEMENTED_POLICY_NAME{"irods_policy_query_processor"};

    auto rule_name_is_supported(const std::string& _rule_name) {
        return (IMPLEMENTED_POLICY_NAME == _rule_name);
    } // rule_name_is_supported

    using json = nlohmann::json;

    void apply_policy(
          ruleExecInfo_t*    _rei
        , const std::string& _parameter_string
        , const std::string& _configuration_string)
    {
        rodsLog(
            LOG_NOTICE,
            "[%s]::[%s] - [%s]",
            IMPLEMENTED_POLICY_NAME.c_str(),
            _parameter_string.c_str(),
            _configuration_string.c_str());

        try {
            using result_row = irods::query_processor<rsComm_t>::result_row;

            auto parameters{json::parse(_parameter_string)};

            std::string query_string{parameters.at("query_string")};
            int         query_limit{parameters.at("query_limit")};
            auto        query_type{irods::query<rsComm_t>::convert_string_to_query_type(parameters.at("query_type"))};
            std::string policy_to_invoke{parameters.at("policy_to_invoke")};
            int number_of_threads{4};
            if(!parameters["number_of_threads"].empty()) {
                number_of_threads = parameters["number_of_threads"];
            }

            auto job = [&](const result_row& _results) {
                auto res_arr = json::array();
                for(auto& r : _results) {
                    res_arr.push_back(r);
                }

                std::list<boost::any> arguments;
                arguments.push_back(boost::any(res_arr.dump()));
                arguments.push_back(boost::any(_configuration_string));
                irods::invoke_policy(_rei, policy_to_invoke, arguments);
            }; // job

            irods::thread_pool thread_pool{number_of_threads};
            irods::query_processor<rsComm_t> qp(query_string, job, query_limit, query_type);
            auto future = qp.execute(thread_pool, *_rei->rsComm);
            auto errors = future.get();
            if(errors.size() > 0) {
                for(auto& e : errors) {
                    rodsLog(
                        LOG_ERROR,
                        "scheduling failed [%d]::[%s]",
                        std::get<0>(e),
                        std::get<1>(e).c_str());
                }

                THROW(
                    SYS_INVALID_OPR_TYPE,
                    boost::format(
                    "scheduling failed for [%d] objects for query [%s]")
                    % errors.size()
                    % query_string.c_str());
            }

        }
        catch(const json::exception& e) {
            rodsLog(LOG_ERROR, "%s", e.what());
        }
        catch(const irods::exception& e) {
            // if nothing of interest is found, thats not an error
            if(CAT_NO_ROWS_FOUND == e.code()) {
            }
            else {
                irods::log(e);
                irods::exception_to_rerror(
                    e, _rei->rsComm->rError);
            }
        }

    } // apply_policy

} // namespace

irods::error start(
      irods::default_re_ctx&
    , const std::string& _instance_name )
{
    // capture plugin instance name
    plugin_instance_name = _instance_name;

    // register the policy implementation name as supported by this plugin
    RuleExistsHelper::Instance()->registerRuleRegex(IMPLEMENTED_POLICY_NAME);

    return SUCCESS();
}

irods::error stop(
      irods::default_re_ctx&
    , const std::string& )
{
    return SUCCESS();
}

irods::error rule_exists(
      irods::default_re_ctx&
    , const std::string& _rule_name
    , bool&              _return_value)
{
    _return_value = rule_name_is_supported(_rule_name);
    return SUCCESS();
}

irods::error list_rules(
      irods::default_re_ctx&
    , std::vector<std::string>& _rules)
{
    _rules.push_back(IMPLEMENTED_POLICY_NAME);
    return SUCCESS();
}

irods::error exec_rule(
      irods::default_re_ctx&
    , const std::string&     _rule_name
    , std::list<boost::any>& _arguments
    , irods::callback        _eff_hdlr)
{
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
            auto parameters_string{boost::any_cast<std::string>(*it)}; ++it;
            auto configuration_string{boost::any_cast<std::string>(*it)};

            // invoke example policy given our arguments
            apply_policy(
                rei,
                parameters_string,
                configuration_string);
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
      irods::default_re_ctx&
    , const std::string&
    , msParamArray_t*
    , const std::string&
    , irods::callback )
{
    return ERROR(
            RULE_ENGINE_CONTINUE,
            "exec_rule_text is not supported");
} // exec_rule_text

irods::error exec_rule_expression(
      irods::default_re_ctx&
    , const std::string&
    , msParamArray_t*
    , irods::callback)
{
    return ERROR(
            RULE_ENGINE_CONTINUE,
            "exec_rule_expression is not supported");
} // exec_rule_expression

extern "C"
irods::pluggable_rule_engine<irods::default_re_ctx>* plugin_factory(
    const std::string& _inst_name,
    const std::string& _context )
{
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




