
#include "irods_query.hpp"
#include "irods_re_plugin.hpp"
#include "irods_re_ruleexistshelper.hpp"
#include "irods_server_api_call.hpp"
#include "irods_hierarchy_parser.hpp"
#include "filesystem.hpp"
#include "utilities.hpp"

#include "rsDataObjRepl.hpp"
#include "physPath.hpp"
#include "apiNumber.h"

#include "json.hpp"

#include <boost/any.hpp>

namespace {
    const std::string IMPLEMENTED_POLICY_NAME{"irods_policy_data_replication"};

    auto rule_name_is_supported(const std::string& _rule_name)
    {
        return (IMPLEMENTED_POLICY_NAME == _rule_name);
    } // rule_name_is_supported

    void replicate_object_to_resource(
          rsComm_t*          _comm
        , const std::string& _object_path
        , const std::string& _source_resource
        , const std::string& _destination_resource)
    {
        dataObjInp_t data_obj_inp{};
        rstrcpy(data_obj_inp.objPath, _object_path.c_str(), MAX_NAME_LEN);
        data_obj_inp.createMode = getDefFileMode();
        addKeyVal(&data_obj_inp.condInput, RESC_NAME_KW,      _source_resource.c_str());
        addKeyVal(&data_obj_inp.condInput, DEST_RESC_NAME_KW, _destination_resource.c_str());

        if(_comm->clientUser.authInfo.authFlag >= LOCAL_PRIV_USER_AUTH) {
            addKeyVal(&data_obj_inp.condInput, ADMIN_KW, "true" );
        }

        transferStat_t* trans_stat{};
        const auto repl_err = irods::server_api_call(DATA_OBJ_REPL_AN, _comm, &data_obj_inp, &trans_stat);
        free(trans_stat);
        if(repl_err < 0) {
            THROW(repl_err,
                boost::format("failed to migrate [%s] to [%s]") %
                _object_path % _destination_resource);

        }
    } // replicate_object_to_resource

} // namespace

std::string plugin_instance_name{};

irods::error start(
      irods::default_re_ctx&
    , const std::string& _instance_name)
{
    plugin_instance_name = _instance_name;
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
    , const std::string&
    , std::list<boost::any>& _arguements
    , irods::callback        _eff_hdlr)
{
    ruleExecInfo_t* rei{};
    const auto err = _eff_hdlr("unsafe_ms_ctx", &rei);
    if(!err.ok()) {
        return err;
    }

    using json = nlohmann::json;

    try {
        auto it = _arguements.begin();
        std::string parameter_string{ boost::any_cast<std::string>(*it) }; ++it;
        std::string configuration_string{ boost::any_cast<std::string>(*it) };

        auto parameters{json::parse(parameter_string)};
        std::string object_path{}, source_resource{}, destination_resource{};

        // output from query processor is an array of results
        if(parameters.is_array()) {
            using fsp = irods::experimental::filesystem::path;

            fsp coll{parameters[0]};
            fsp data{parameters[1]};

            auto p = coll / data;
            object_path = p.string();
            source_resource = parameters[2];
        }
        else {
            object_path = parameters["obj_path"];

            auto param_source_resource = parameters["source_resource"];
            if(!param_source_resource.empty()) {
                source_resource = param_source_resource;
            }
            else {
                std::string resc_hier{};
                auto param_resc_hier = parameters["cond_input"]["resc_hier"];
                if(param_resc_hier.empty()) {
                    THROW(
                        SYS_INVALID_INPUT_PARAM,
                        boost::format("%s - source_resource or resc_hier not provided")
                        % IMPLEMENTED_POLICY_NAME);
                }

                resc_hier = param_resc_hier;
                irods::hierarchy_parser parser(resc_hier);
                source_resource = parser.first_resc();
            }

            auto param_destination_resource = parameters["destination_resource"];
            if(!param_destination_resource.empty()) {
                destination_resource = param_destination_resource;
            }
        }

        if(!destination_resource.empty()) {
            replicate_object_to_resource(
                rei->rsComm,
                object_path,
                source_resource,
                destination_resource);
        }
        else {
            if(configuration_string.empty()) {
                THROW(
                    SYS_INVALID_INPUT_PARAM,
                    boost::format("%s - destination_resource is empty and configuration is not provided")
                    % IMPLEMENTED_POLICY_NAME);
            }

            auto configuration{json::parse(configuration_string)};
            auto param_destination_resource = configuration["destination_resource"];
            if(!param_destination_resource.empty()) {
                destination_resource = param_destination_resource;
                replicate_object_to_resource(
                    rei->rsComm,
                    object_path,
                    source_resource,
                    destination_resource);
            }
            else {
                auto src_dst_map{configuration.at("source_to_destination_map")};
                if(src_dst_map.empty()) {
                    THROW(
                        SYS_INVALID_INPUT_PARAM,
                        boost::format("%s - destination_resource or source_to_destination_map not provided")
                        % IMPLEMENTED_POLICY_NAME);
                }
                auto dst_resc_arr{src_dst_map.at(source_resource)};
                auto destination_resources = dst_resc_arr.get<std::vector<std::string>>();
                for( auto& dest : destination_resources) {
                    replicate_object_to_resource(
                        rei->rsComm,
                        object_path,
                        source_resource,
                        dest);
                }
            }
        }

    }
    catch(const  std::invalid_argument& _e) {
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
            INVALID_ANY_CAST,
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
        return irods::error(_e);
    }

    return err;

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




