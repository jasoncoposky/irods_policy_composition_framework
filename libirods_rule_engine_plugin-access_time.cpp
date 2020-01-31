
#include "irods_query.hpp"
#include "irods_re_plugin.hpp"
#include "irods_re_ruleexistshelper.hpp"
#include "irods_virtual_path.hpp"
#include "utilities.hpp"

#include "rsModAVUMetadata.hpp"
#include "rsOpenCollection.hpp"
#include "rsReadCollection.hpp"
#include "rsCloseCollection.hpp"

#include <boost/any.hpp>

#include "json.hpp"
using json = nlohmann::json;

namespace {
    std::string plugin_instance_name{};
    const std::string IMPLEMENTED_POLICY_NAME{"irods_policy_access_time"};

    auto rule_name_is_supported(const std::string& _rule_name) {
        return (IMPLEMENTED_POLICY_NAME == _rule_name);
    } // rule_name_is_supported

    void update_access_time_for_data_object(
        rsComm_t*          _comm,
        const std::string& _logical_path,
        const std::string& _attribute) {

        auto ts = std::to_string(std::time(nullptr));
        modAVUMetadataInp_t avuOp{
            "set",
            "-d",
            const_cast<char*>(_logical_path.c_str()),
            const_cast<char*>(_attribute.c_str()),
            const_cast<char*>(ts.c_str()),
            ""};

        auto status = rsModAVUMetadata(_comm, &avuOp);
        if(status < 0) {
            THROW(
                status,
                boost::format("failed to set access time for [%s]") %
                _logical_path);
        }
    } // update_access_time_for_data_object

    void apply_access_time_to_collection(
        rsComm_t*          _comm,
        int                _handle,
        const std::string& _attribute) {
        collEnt_t* coll_ent{nullptr};
        int err = rsReadCollection(_comm, &_handle, &coll_ent);
        while(err >= 0) {
            if(DATA_OBJ_T == coll_ent->objType) {
                const auto& vps = irods::get_virtual_path_separator();
                std::string lp{coll_ent->collName};
                lp += vps;
                lp += coll_ent->dataName;
                update_access_time_for_data_object(_comm, lp, _attribute);
            }
            else if(COLL_OBJ_T == coll_ent->objType) {
                collInp_t coll_inp;
                memset(&coll_inp, 0, sizeof(coll_inp));
                rstrcpy(
                    coll_inp.collName,
                    coll_ent->collName,
                    MAX_NAME_LEN);
                int handle = rsOpenCollection(_comm, &coll_inp);
                apply_access_time_to_collection(_comm, handle, _attribute);
                rsCloseCollection(_comm, &handle);
            }

            err = rsReadCollection(_comm, &_handle, &coll_ent);
        } // while
    } // apply_access_time_to_collection

    void apply_access_time_policy(
        rsComm_t*              _comm,
        std::list<boost::any>& _args) {
        try {
            if(_args.size() != 2) {
                THROW(
                    SYS_INVALID_INPUT_PARAM,
                    "invalid number of arguments");
            }

            auto it = _args.begin();
            auto params_str{boost::any_cast<std::string>(*it)}; ++it;
            auto cfg_str{boost::any_cast<std::string>(*it)};
            rodsLog(LOG_DEBUG,
                    "[%s] json string [%s]",
                    IMPLEMENTED_POLICY_NAME.c_str(),
                    params_str.c_str());

            json params_obj;
            if(!params_str.empty()) {
                params_obj = json::parse(params_str);
            }
            else {
                THROW(
                    SYS_INVALID_INPUT_PARAM,
                    "parameters json string is empty");
            }

            json cfg_obj;
            if(!cfg_str.empty()) {
                cfg_obj = json::parse(cfg_str);
            }
            else {
                rodsLog(
                    LOG_DEBUG,
                    "[%s] configuration json string is empty.",
                    IMPLEMENTED_POLICY_NAME.c_str());
            }


            bool collection_operation{false};
            auto cond_input = params_obj["cond_input"];
            if(!cond_input.empty()) {
                auto coll_kw = cond_input[COLLECTION_KW];
                if(!coll_kw.empty()) {
                    collection_operation = true;
                }
            }

            std::string attribute{"irods::access_time"};
            if(!cfg_obj.empty() && !cfg_obj["attribute"].empty()) {
                attribute = cfg_obj["attribute"];
            }

            std::string obj_path{params_obj["obj_path"]};
            if(obj_path.empty()) {
                THROW(
                    SYS_INVALID_INPUT_PARAM,
                    "missing object path parameter");
            }

            if(!collection_operation) {
                update_access_time_for_data_object(_comm, obj_path, attribute);
            }
            else {
                // register a collection
                collInp_t coll_inp;
                memset(&coll_inp, 0, sizeof(coll_inp));
                rstrcpy(
                    coll_inp.collName,
                    obj_path.c_str(),
                    MAX_NAME_LEN);
                int handle = rsOpenCollection(
                                 _comm,
                                 &coll_inp);
                if(handle < 0) {
                    THROW(
                        handle,
                        boost::format("failed to open collection [%s]") %
                        obj_path);
                }

                apply_access_time_to_collection(_comm, handle, attribute);
            }
        }
        catch(const boost::bad_any_cast& _e) {
            THROW( INVALID_ANY_CAST, _e.what() );
        }
        catch(const nlohmann::detail::type_error& _e) {
            THROW( SYS_INVALID_INPUT_PARAM, _e.what() );
        }
    } // apply_access_time_policy

} // namespace

irods::error start(
    irods::default_re_ctx&,
    const std::string& _instance_name ) {
    plugin_instance_name = _instance_name;
    RuleExistsHelper::Instance()->registerRuleRegex(IMPLEMENTED_POLICY_NAME);
    return SUCCESS();
} // start

irods::error stop(
    irods::default_re_ctx&,
    const std::string& ) {
    return SUCCESS();
} // stop

irods::error rule_exists(
    irods::default_re_ctx&,
    const std::string& _rule_name,
    bool&              _return_value) {
    _return_value = rule_name_is_supported(_rule_name);
    return SUCCESS();
} // rule_exists

irods::error list_rules(
    irods::default_re_ctx&,
    std::vector<std::string>& _rules) {
    _rules.push_back(IMPLEMENTED_POLICY_NAME);
    return SUCCESS();
} // list_rules

irods::error exec_rule(
    irods::default_re_ctx&,
    const std::string&     _rule_name,
    std::list<boost::any>& _arguments,
    irods::callback        _eff_hdlr) {

    ruleExecInfo_t* rei{};
    const auto err = _eff_hdlr("unsafe_ms_ctx", &rei);
    if(!err.ok()) {
        return ERROR(SYS_NOT_SUPPORTED, err.result());
    }

    try {
        if(IMPLEMENTED_POLICY_NAME == _rule_name) {
            apply_access_time_policy(rei->rsComm, _arguments);
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




