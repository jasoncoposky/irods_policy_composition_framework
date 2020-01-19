
#include "irods_re_plugin.hpp"
#include "irods_re_ruleexistshelper.hpp"
#include "event_handler_data_object_modified_utilities.hpp"
#include "event_handler_data_object_modified_configuration.hpp"
#include "rcMisc.h"

#include <boost/any.hpp>
#include "objDesc.hpp"

#include "boost/lexical_cast.hpp"

#include "utilities.hpp"

#include "json.hpp"
using json = nlohmann::json;

// Persistent L1 File Descriptor Table
extern l1desc_t L1desc[NUM_L1_DESC];

namespace {
    std::unique_ptr<irods::event_handler_data_object_modified_configuration> config;
    std::map<int, std::string> objects_in_flight;
    std::string plugin_instance_name{};
    const std::set<std::string> consumed_policy_enforcement_points{
                                    "pep_api_data_obj_create_post",
                                    "pep_api_data_obj_open_post",
                                    "pep_api_data_obj_close_post",
                                    "pep_api_data_obj_put_post",
                                    "pep_api_data_obj_repl_post",
                                    "pep_api_data_obj_get_post",
                                    "pep_api_data_obj_unlink_post",
                                    "pep_api_data_obj_rename_post",
                                    "pep_api_phy_path_reg_post"};

    auto rule_name_is_supported(const std::string& _rule_name) {
        return (consumed_policy_enforcement_points.find(_rule_name) !=
                consumed_policy_enforcement_points.end());
    } // rule_name_is_supported

    void event_data_object_modified(
        const std::string&           _rule_name,
        ruleExecInfo_t*              _rei,
        const std::list<boost::any>& _arguments) {

        try {
            // all three PEPs use the same signature
            if("pep_api_data_obj_put_post"    == _rule_name ||
               "pep_api_data_obj_get_post"    == _rule_name ||
               "pep_api_data_obj_unlink_post" == _rule_name ||
               "pep_api_data_obj_repl_post"   == _rule_name ||
               "pep_api_phy_path_reg_post"    == _rule_name) {
                auto it = _arguments.begin();
                std::advance(it, 2);
                if(_arguments.end() == it) {
                    THROW(
                        SYS_INVALID_INPUT_PARAM,
                        "invalid number of arguments");
                }

                auto obj_inp = boost::any_cast<dataObjInp_t*>(*it);
                auto jobj = irods::serialize_dataObjInp_to_json(*obj_inp);

                std::list<boost::any> args;
                args.push_back(boost::any(plugin_instance_name));
                args.push_back(boost::any(_rule_name));
                args.push_back(boost::any(jobj.dump()));

                for(auto& pn : config->policies_to_invoke) {
                    rodsLog(
                        LOG_DEBUG,
                        "EVENT_DATA_OBJECT_MODIFIED - 1. Invoke Policy for Data Modification Event : [%s]",
                        pn.c_str());
                    irods::invoke_policy(_rei, pn, args);
                }


            }
            else if("pep_api_data_obj_rename_post" == _rule_name) {
                auto it = _arguments.begin();
                std::advance(it, 2);
                if(_arguments.end() == it) {
                    THROW(
                        SYS_INVALID_INPUT_PARAM,
                        "invalid number of arguments");
                }

                auto copy_inp = boost::any_cast<dataObjCopyInp_t*>(*it);
                auto src_jobj = irods::serialize_dataObjInp_to_json(copy_inp->srcDataObjInp);
                auto dst_jobj = irods::serialize_dataObjInp_to_json(copy_inp->destDataObjInp);

                std::list<boost::any> args;
                args.push_back(boost::any(plugin_instance_name));
                args.push_back(boost::any(_rule_name));
                args.push_back(boost::any(src_jobj.dump()));
                for(auto& pn : config->policies_to_invoke) {
                    rodsLog(
                        LOG_DEBUG,
                        "EVENT_DATA_OBJECT_MODIFIED - 2 Source. Invoke Policy for Data Rename Event : [%s]",
                        pn.c_str());
                    irods::invoke_policy(_rei, pn, args);
                }

                args.clear();
                args.push_back(boost::any(plugin_instance_name));
                args.push_back(boost::any(_rule_name));
                args.push_back(boost::any(dst_jobj.dump()));
                for(auto& pn : config->policies_to_invoke) {
                    rodsLog(
                        LOG_DEBUG,
                        "EVENT_DATA_OBJECT_MODIFIED - 2 Destination. Invoke Policy for Data Rename Event : [%s]",
                        pn.c_str());
                    irods::invoke_policy(_rei, pn, args);
                }
            }
            // uses the file descriptor table to track modify operations
            // only add an entry if the object is created or opened for write
            else if("pep_api_data_obj_open_post"   == _rule_name ||
                    "pep_api_data_obj_create_post" == _rule_name) {
                auto it = _arguments.begin();
                std::advance(it, 2);
                if(_arguments.end() == it) {
                    THROW(
                        SYS_INVALID_INPUT_PARAM,
                        "invalid number of arguments");
                }
                auto obj_inp = boost::any_cast<dataObjInp_t*>(*it);

                // TODO: determine if a modification is happening first
                int l1_idx{};
                std::string jstr;
                try {
                    std::tie(l1_idx, jstr) = irods::get_index_and_json_from_obj_inp(obj_inp);
                    objects_in_flight[l1_idx] = jstr;
                }
                catch(const irods::exception& _e) {
                    rodsLog(
                       LOG_ERROR,
                       "irods::get_index_and_resource_from_obj_inp failed for [%s]",
                       obj_inp->objPath);
                }
            }
            // uses the tracked file descriptor table operations to invoke policy
            // if changes were actually made to the object
            else if("pep_api_data_obj_close_post" == _rule_name) {
                auto it = _arguments.begin();
                std::advance(it, 2);
                if(_arguments.end() == it) {
                    THROW(
                        SYS_INVALID_INPUT_PARAM,
                        "invalid number of arguments");
                }

                const auto opened_inp = boost::any_cast<openedDataObjInp_t*>(*it);
                const auto l1_idx = opened_inp->l1descInx;
                std::string jstr;
                jstr = objects_in_flight[l1_idx];

                auto jobj = json::parse(jstr);
                std::string open_flags_str = jobj["open_flags"];
                auto open_flags = boost::lexical_cast<int>(open_flags_str);
                bool create = (open_flags & O_RDWR ) == O_RDWR;
                create = create & ((open_flags & O_WRONLY) == O_WRONLY);
                create = create & ((open_flags & O_CREAT)  == O_CREAT);
                rodsLog(LOG_NOTICE, "XXXX - create mode [%d]", create);


                std::list<boost::any> args;
                args.push_back(boost::any(plugin_instance_name));
                args.push_back(boost::any(_rule_name));
                args.push_back(boost::any(jstr));
                for(auto& pn : config->policies_to_invoke) {
                    rodsLog(
                        LOG_DEBUG,
                        "EVENT_DATA_OBJECT_MODIFIED - 3. Invoke Policy for Data Stream Event : [%s]",
                        pn.c_str());
                    irods::invoke_policy(_rei, pn, args);
                }
            } // else if
        }
        catch(const std::invalid_argument& _e) {
            rodsLog(LOG_ERROR, "%s", _e.what());
        }
        catch(const boost::bad_any_cast& _e) {
            rodsLog(LOG_ERROR, "%s", _e.what());
        }
        catch(const boost::bad_lexical_cast& _e) {
            rodsLog(LOG_ERROR, "%s", _e.what());
        }
        catch(const irods::exception& _e) {
            rodsLog(LOG_ERROR, "%s", _e.what());
        }

    } // event_data_object_modified

} // namespace

irods::error start(
    irods::default_re_ctx&,
    const std::string& _instance_name ) {
    // capture plugin instance name
    plugin_instance_name = _instance_name;

    // load the plugin specific configuration for this instance
    config = std::make_unique<irods::event_handler_data_object_modified_configuration>(plugin_instance_name);

    // build a list of pep strings for the regexp
    std::string regex{};
    for( auto& s : consumed_policy_enforcement_points) {
        regex += s + " || ";
    }
    // trim trailing " || "
    regex.substr(regex.size()-4);

    // register the event handler's peps as implemented by this plugin
    RuleExistsHelper::Instance()->registerRuleRegex(regex);

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
    for( auto& s : consumed_policy_enforcement_points) {
        _rules.push_back(s);
    }
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
        // always return SYS_NOT_SUPPORTED given an error in an Event Handler
        // which allows the REPF to continue trying other plugins or rule bases
        return ERROR(SYS_NOT_SUPPORTED, err.result());
    }

    try {
        // given a specific PEP, invoke the event handler
        event_data_object_modified(_rule_name, rei, _arguments);
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

    // this code signals to the REPF that we were successfull but should continue
    // looking for further implementations of the same policy enforcement point
    return CODE(RULE_ENGINE_CONTINUE);

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




