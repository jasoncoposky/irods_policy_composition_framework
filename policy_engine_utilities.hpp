
#include "irods_re_plugin.hpp"
#include "irods_exception.hpp"
#include "irods_query.hpp"
#include "irods_hierarchy_parser.hpp"
#include "rodsError.h"

#include "filesystem.hpp"
#include "json.hpp"

namespace irods {

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

    using json = nlohmann::json;

    template<typename T>
    T extract_object_parameter(
          const std::string& _name
        , const json&        _params)
    {
        if(_params.empty()) {
            return T{};
        }

        if(_params.find(_name) == _params.end()) {
            return T{};
        }
        auto foo = _params.at(_name);
        return _params.at(_name);
    }

    struct TagFirstResc {} tag_first_resc;
    struct TagLastResc  {} tag_last_resc;

    auto parse_hierarchy(const irods::hierarchy_parser& _p, TagFirstResc) {return _p.first_resc();}
    auto parse_hierarchy(const irods::hierarchy_parser& _p, TagLastResc) {return _p.last_resc();}

    template<typename TAG_TYPE>
    auto extract_dataobj_inp_parameters(
          const json& _params
        , TAG_TYPE    T)
    {
        std::string user_name{}, object_path{}, source_resource{}, destination_resource{};

        auto comm_obj = _params["comm"];
        user_name = extract_object_parameter<std::string>("proxy_user_name", comm_obj);

        if(user_name.empty()) {
            user_name = extract_object_parameter<std::string>("user_name", _params);
        }

        object_path = extract_object_parameter<std::string>("obj_path", _params);
        if(object_path.empty()) {
           object_path = extract_object_parameter<std::string>("object_path", _params);
        }

        source_resource = extract_object_parameter<std::string>("source_resource", _params);
        destination_resource = extract_object_parameter<std::string>("destination_resource", _params);

        auto cond_input = _params["cond_input"];

        if(source_resource.empty()) {
            if(cond_input.find("resc_hier") == cond_input.end()) {
                THROW(
                    SYS_INVALID_INPUT_PARAM,
                    "source_resource or resc_hier not provided");
            }

            std::string resc_hier = _params["cond_input"]["resc_hier"];
            irods::hierarchy_parser parser(resc_hier);
            source_resource = parse_hierarchy(parser, T);
        }

        if(destination_resource.empty()) {
            if(cond_input.find("dest_resc_hier") != cond_input.end()) {
                std::string dest_resc_hier = _params["cond_input"]["dest_resc_hier"];
                irods::hierarchy_parser parser(dest_resc_hier);
                destination_resource = parse_hierarchy(parser, T);
            }
        }

        return std::make_tuple(user_name, object_path, source_resource, destination_resource);
    }

    template<typename T>
    T extract_array_parameter(
          json   _params
        , size_t _idx)
    {
        return _params[_idx];
    }

    template <typename T, size_t... Is>
    auto extract_array_parameters_impl(
          json _params
        , std::index_sequence<Is...>)
    {
        return std::make_tuple(extract_array_parameter<T>(_params, Is)...);
    }

    template<size_t N, typename T>
    auto extract_array_parameters(
          json _params)
    {
        if(!_params.is_array()) {
            THROW(
                SYS_INVALID_INPUT_PARAM,
                "parameters is not a json array");
        }

        return extract_array_parameters_impl<T>(_params, std::make_index_sequence<N>{});

    } // extract_array_parameters

    auto get_metadata_for_resource(
          rsComm_t*          _comm
        , const std::string& _meta_attr_name
        , const std::string& _resource_name ) {
        std::string query_str {
            boost::str(
                    boost::format("SELECT META_RESC_ATTR_VALUE, META_RESC_ATTR_UNITS WHERE META_RESC_ATTR_NAME = '%s' and RESC_NAME = '%s'") %
                    _meta_attr_name %
                    _resource_name) };
        irods::query<rsComm_t> qobj{_comm, query_str, 1};
        if(qobj.size() > 0) {
            return std::make_tuple(qobj.front()[0], qobj.front()[1]);
        }

        return std::make_tuple(std::string{}, std::string{});
    } // get_metadata_for_resource

} // namespace irods
