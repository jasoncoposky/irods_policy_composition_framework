
#include "policy_composition_framework_utilities.hpp"
#include "policy_composition_framework_parameter_capture.hpp"

#include "irods_resource_backport.hpp"

#include "rcMisc.h"
#include "objDesc.hpp"

#include "boost/lexical_cast.hpp"
#include "fmt/format.h"

// Persistent L1 File Descriptor Table
extern l1desc_t L1desc[NUM_L1_DESC];

namespace irods::policy_composition {

    auto any_to_string(boost::any& _a) {
        if(_a.type() == typeid(std::string)) {
            return boost::any_cast<std::string>(_a);
        }
        else if(_a.type() == typeid(std::string*)) {
            return *boost::any_cast<std::string*>(_a);
        }
        else if(_a.type() == typeid(msParam_t*)) {
            msParam_t* msp = boost::any_cast<msParam_t*>(_a);
            if(msp->type == STR_MS_T) {
                return std::string{static_cast<char*>(msp->inOutStruct)};
            }
            else {
                rodsLog(
                    LOG_ERROR,
                    "not a string type [%s]",
                    msp->type);
            }
        }

        THROW(
           SYS_INVALID_INPUT_PARAM,
           boost::format("parameter is not a string [%s]")
           % _a.type().name());
    } // any_to_string

    void exception_to_rerror(
        const irods::exception& _exception,
        rError_t&               _error) {
        std::string msg;
        for(const auto& i : _exception.message_stack()) {
            msg += i;
        }

        addRErrorMsg(
            &_error,
            _exception.code(),
            msg.c_str());
    } // exception_to_rerror

    void exception_to_rerror(
        const int   _code,
        const char* _what,
        rError_t&   _error) {

        addRErrorMsg(
            &_error,
            _code,
            _what);
    } // exception_to_rerror

    auto collapse_error_stack(
        rError_t& _error) {

        std::stringstream ss;

        for(int i = 0; i < _error.len; ++i) {

            rErrMsg_t* err_msg = _error.errMsg[i];

            if(err_msg->status != STDOUT_STATUS) {
                ss << "status: " << err_msg->status << " ";
            }

            ss << err_msg->msg << " - ";
        }

        return ss.str();

    } // collapse_error_stack

    void invoke_policy(
          ruleExecInfo_t*        _rei
        , const std::string&     _action
        , std::list<boost::any>& _args)
    {
        irods::rule_engine_context_manager<
            irods::unit,
            ruleExecInfo_t*,
            irods::AUDIT_RULE> re_ctx_mgr(
                    irods::re_plugin_globals->global_re_mgr,
                    _rei);
        irods::error err = re_ctx_mgr.exec_rule(_action, irods::unpack(_args));
        if(!err.ok()) {
            if(_rei->status < 0) {
                std::string msg = collapse_error_stack(_rei->rsComm->rError);
                THROW(_rei->status, msg);
            }

            THROW(err.code(), err.result());
        }
    } // invoke_policy

    auto advance_or_throw(
        const arguments_type& _args
      , const uint32_t        _num) -> arguments_type::const_iterator
    {
        auto it = _args.cbegin();

        std::advance(it, _num);
        if(_args.end() == it) {
            THROW(
                SYS_INVALID_INPUT_PARAM,
                "invalid number of arguments");
        }

        return it;

    } // advance_or_throw

    auto pep_to_event(const event_map_type& _p2e, const std::string& _pep) -> std::string
    {
        const auto prefix = std::string{"pep_api_"};

        // remove the prefix
        auto pos = _pep.find(prefix);
        if(std::string::npos == pos) {
            return "UNSUPPORTED";
        }

        auto tmp = _pep.substr(prefix.size());

        // remove the suffix
        pos = tmp.find_last_of("_");
        if(std::string::npos == pos) {
            return "UNSUPPORTED";
        }

        tmp = tmp.substr(0, pos);

        try {
            return _p2e.at(tmp);
        }
        catch(const std::exception& _e) {
            THROW(
                SYS_INVALID_INPUT_PARAM,
                fmt::format("failed to map event for pep {}", tmp));
        }

    } // pep_to_event

    auto get_index_and_json_from_obj_inp(const dataObjInp_t* _inp) -> std::tuple<int, json>
    {
        int l1_idx{};
        dataObjInfo_t* obj_info{};
        for(const auto& l1 : L1desc) {
            if(FD_INUSE != l1.inuseFlag) {
                continue;
            }

            if(!strcmp(l1.dataObjInp->objPath, _inp->objPath)) {
                obj_info = l1.dataObjInfo;
                l1_idx = &l1 - L1desc;
            }
        }

        if(nullptr == obj_info) {
            THROW(
                SYS_INVALID_INPUT_PARAM,
                "no object found");
        }

        auto jobj = serialize_dataObjInp_to_json(*_inp);

        return std::make_tuple(l1_idx, jobj);

    } // get_index_and_resource_from_obj_inp

    auto serialize_generalAdminInp_to_json(const generalAdminInp_t& _inp) -> json
    {
        json j;
        j["action"] = _inp.arg0;
        j["target"] = _inp.arg1;
        j["arg2"]   = _inp.arg2;
        j["arg3"]   = _inp.arg3;
        j["arg4"]   = _inp.arg4;
        j["arg5"]   = _inp.arg5;
        j["arg6"]   = _inp.arg6;
        j["arg7"]   = _inp.arg7;
        j["arg8"]   = _inp.arg8;
        j["arg9"]   = _inp.arg9;

        return j;
    } // serialize_generalAdminInp_to_json

    auto serialize_keyValPair_to_json(const keyValPair_t& _kvp) -> json
    {
        json j;
        if(_kvp.len > 0) {
            for(int i = 0; i < _kvp.len; ++i) {
               if(_kvp.keyWord && _kvp.keyWord[i]) {
                    if(_kvp.value && _kvp.value[i]) {
                        j[_kvp.keyWord[i]] = _kvp.value[i];
                    }
                    else {
                        j[_kvp.keyWord[i]] = "empty_value";
                    }
                }
            }
        } else {
            j["keyValPair_t"] = "nullptr";
        }

        return j;

    } // serialize_keyValPair_to_json

    auto serialize_collInp_to_json(const collInp_t& _inp) -> json
    {
        json j;
        j["logical_path"] = _inp.collName;
        j["flags"]        = boost::lexical_cast<std::string>(_inp.flags);
        j["opr_type"]     = boost::lexical_cast<std::string>(_inp.oprType);
        j["cond_input"]   = serialize_keyValPair_to_json(_inp.condInput);

        return j;

    } // seralize_collInp_to_json

    auto serialize_dataObjInp_to_json(const dataObjInp_t& _inp) -> json
    {
        json j;
        j["logical_path"] = _inp.objPath;
        j["create_mode"]  = boost::lexical_cast<std::string>(_inp.createMode);
        j["open_flags"]   = boost::lexical_cast<std::string>(_inp.openFlags);
        j["offset"]       = boost::lexical_cast<std::string>(_inp.offset);
        j["data_size"]    = boost::lexical_cast<std::string>(_inp.dataSize);
        j["num_threads"]  = boost::lexical_cast<std::string>(_inp.numThreads);
        j["opr_type"]     = boost::lexical_cast<std::string>(_inp.oprType);
        j["cond_input"]   = serialize_keyValPair_to_json(_inp.condInput);

        return j;

    } // seralize_dataObjInp_to_json

    auto serialize_openedDataObjInp_to_json(const openedDataObjInp_t& _inp) -> json
    {
        json j;
        j["l1_desc_inx"]   = boost::lexical_cast<std::string>(_inp.l1descInx);
        j["len"]           = boost::lexical_cast<std::string>(_inp.len);
        j["whence"]        = boost::lexical_cast<std::string>(_inp.whence);
        j["opr_type"]      = boost::lexical_cast<std::string>(_inp.oprType);
        j["offset"]        = boost::lexical_cast<std::string>(_inp.offset);
        j["bytes_written"] = boost::lexical_cast<std::string>(_inp.bytesWritten);
        j["cond_input"]    = serialize_keyValPair_to_json(_inp.condInput);

        return j;

    } // seralize_openedDataObjInp_to_json

    auto serialize_rsComm_to_json(rsComm_t* _comm) -> json
    {
        json j;
        if (_comm) {
            j["client_addr"] = _comm->clientAddr;

            if(_comm->auth_scheme) {j["auth_scheme"] = _comm->auth_scheme;}

            j["proxy_user_name"] = _comm->proxyUser.userName;
            j["proxy_rods_zone"] = _comm->proxyUser.rodsZone;
            j["proxy_user_type"] = _comm->proxyUser.userType;
            j["proxy_sys_uid"] = boost::lexical_cast<std::string>(_comm->proxyUser.sysUid);
            j["proxy_auth_info_auth_scheme"] = _comm->proxyUser.authInfo.authScheme;
            j["proxy_auth_info_auth_flag"] = boost::lexical_cast<std::string>(_comm->proxyUser.authInfo.authFlag);
            j["proxy_auth_info_flag"] = boost::lexical_cast<std::string>(_comm->proxyUser.authInfo.flag);
            j["proxy_auth_info_ppid"] = boost::lexical_cast<std::string>(_comm->proxyUser.authInfo.ppid);
            j["proxy_auth_info_host"] = _comm->proxyUser.authInfo.host;
            j["proxy_auth_info_auth_str"] = _comm->proxyUser.authInfo.authStr;
            j["proxy_user_other_info_user_info"] = _comm->proxyUser.userOtherInfo.userInfo;
            j["proxy_user_other_info_user_comments"] = _comm->proxyUser.userOtherInfo.userComments;
            j["proxy_user_other_info_user_create"] = _comm->proxyUser.userOtherInfo.userCreate;
            j["proxy_user_other_info_user_modify"] = _comm->proxyUser.userOtherInfo.userModify;

            j["user_user_name"] = _comm->clientUser.userName;
            j["user_rods_zone"] = _comm->clientUser.rodsZone;
            j["user_user_type"] = _comm->clientUser.userType;
            j["user_sys_uid"] = boost::lexical_cast<std::string>(_comm->clientUser.sysUid);
            j["user_auth_info_auth_scheme"] = _comm->clientUser.authInfo.authScheme;
            j["user_auth_info_auth_flag"] = boost::lexical_cast<std::string>(_comm->clientUser.authInfo.authFlag);
            j["user_auth_info_flag"] = boost::lexical_cast<std::string>(_comm->clientUser.authInfo.flag);
            j["user_auth_info_ppid"] = boost::lexical_cast<std::string>(_comm->clientUser.authInfo.ppid);
            j["user_auth_info_host"] = _comm->clientUser.authInfo.host;
            j["user_auth_info_auth_str"] = _comm->clientUser.authInfo.authStr;
            j["user_user_other_info_user_info"] = _comm->clientUser.userOtherInfo.userInfo;
            j["user_user_other_info_user_comments"] = _comm->clientUser.userOtherInfo.userComments;
            j["user_user_other_info_user_create"] = _comm->clientUser.userOtherInfo.userCreate;
            j["user_user_other_info_user_modify"] = _comm->clientUser.userOtherInfo.userModify;
        } else {
            j["rsComm_ptr"] = "nullptr";
        }

        return j;

    } // serialize_rsComm_ptr

    auto evaluate_metadata_conditional(
          const json& cm           // conditional metadata
        , const json& em) -> bool  // entity metadata
    {
        if(cm.contains("entity_type") &&
           em.contains("entity_type")) {
           if(cm.at("entity_type") != em.at("entity_type")) {
               return false;
           }
        }

        if(cm.contains("operation") &&
           em.contains("operation")) {
            bool found = false;
            for(const auto op : cm.at("operation")) {
                if(op == em.at("operation")) {
                    found = true;
                    break;
                }
            }

            if(!found) {
                return false;
            }
        }

        namespace fs = irods::experimental::filesystem;

        const fs::metadata cmd{
              cm.contains("attribute") ? cm.at("attribute") : ""
            , cm.contains("value")     ? cm.at("value")     : ""
            , cm.contains("units")     ? cm.at("units")     : ""};

        const fs::metadata emd{
              em.contains("attribute") ? em.at("attribute") : ""
            , em.contains("value")     ? em.at("value")     : ""
            , em.contains("units")     ? em.at("units")     : ""};

        if(cmd.attribute.empty() && cmd.value.empty() && cmd.units.empty()) {
            return true;
        }

        bool match{true};

        if(cmd.attribute.size() > 0) {
            match = match && boost::regex_match(
                                 emd.attribute,
                                 boost::regex(cmd.attribute));
        }

        if(cmd.value.size() > 0) {
            match = match && boost::regex_match(
                                 emd.value,
                                 boost::regex(cmd.value));
        }

        if(cmd.units.size() > 0) {
            match = match && boost::regex_match(
                                 emd.units,
                                 boost::regex(cmd.units));
        }

        return match;

    } // evaluate_metadata_conditional

    static bool evaluate_conditionals(
          const json& parameters
        ,       json& policy)
    {
        // look for conditionals
        if(policy.contains("conditional")) {
            std::string user_name{}, logical_path{}, source_resource{}, destination_resource{};
            std::tie(user_name, logical_path, source_resource, destination_resource) =
                capture_parameters(
                      parameters
                    , tag_first_resc);

            if(policy.at("conditional").contains("metadata")) {
                auto cmd = policy.at("conditional").at("metadata");
                auto emd = parameters.at("metadata");
                if(!evaluate_metadata_conditional(cmd, emd)) {
                        return false;
                }

                policy.at("parameters").at("conditional").at("metadata") = parameters.at("metadata");
            }
            if(policy.at("conditional").contains("logical_path")) {
                auto cond_regex = boost::regex(policy.at("conditional").at("logical_path"));
                if(!boost::regex_match(logical_path, cond_regex)) {
                    return false;
                }
            }
            if(policy.at("conditional").contains("source_resource") &&
               !source_resource.empty()) {
                auto cond_regex = boost::regex(policy.at("conditional").at("source_resource"));
                if(!boost::regex_match(source_resource, cond_regex)) {
                    return false;
                }
            }
            if(policy.at("conditional").contains("destination_resource") &&
               !source_resource.empty()) {
                auto cond_regex = boost::regex(policy.at("conditional").at("destination_resource"));
                if(!boost::regex_match(destination_resource, cond_regex)) {
                    return false;
                }
            }
            if(policy.at("conditional").contains("user_name") &&
               !user_name.empty()) {
                auto cond_regex = boost::regex(policy.at("conditional").at("user_name"));
                if(!boost::regex_match(user_name, cond_regex)) {
                    return false;
                }
            }

        } // if conditional

        return true;

    } // evaluate_conditionals

    void invoke_policies_for_event(
          ruleExecInfo_t*    rei
        , const std::string& event
        , const std::string& rule_name
        , const json&        policies_to_invoke
        , const json&        parameters)
    {

        std::list<boost::any> args;
        for(auto policy : policies_to_invoke) {
            auto policy_clauses = policy["active_policy_clauses"];
            if(policy_clauses.empty()) {
                continue;
            }

            for(auto& clause : policy_clauses) {
                std::string suffix{"_"}; suffix += clause;
                if(rule_name.find(suffix) != std::string::npos) {

                    // look for conditionals
                    if(!evaluate_conditionals(parameters, policy)) {
                        continue;
                    } // if conditional

                    auto ops = policy["events"];
                    for(auto& op : ops) {
                        std::string upper_operation{op};
                        std::transform(upper_operation.begin(),
                                       upper_operation.end(),
                                       upper_operation.begin(),
                                       ::toupper);
                        if(upper_operation != event) {
                            continue;
                        }

                        json pam{}, cfg{};

                        if(policy.contains("parameters")) {
                            pam = policy.at("parameters");
                            pam.insert(parameters.begin(), parameters.end());
                        }
                        else {
                            pam = parameters;
                        }

                        if(policy.contains("configuration")) {
                            cfg = policy["configuration"];
                        }

                        std::string pnm{policy["policy"]};
                        std::string params{pam.dump()};
                        std::string config{cfg.dump()};

                        args.clear();
                        args.push_back(boost::any(std::ref(params)));
                        args.push_back(boost::any(std::ref(config)));

                        invoke_policy(rei, pnm, args);
                    } // for ops

                } // if suffix

            } // for policy_clauses

        } // for policy

    } // invoke_policies_for_event

} // namespace irods::event_handler

