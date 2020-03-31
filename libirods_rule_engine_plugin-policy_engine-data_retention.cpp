
#include "policy_engine.hpp"
#include "exec_as_user.hpp"
#include "irods_server_api_call.hpp"
#include "apiNumber.h"
#include "policy_engine_configuration_manager.hpp"

#include "json.hpp"

namespace pe = irods::policy_engine;

namespace {

    struct mode {
        static const std::string remove_all;
        static const std::string trim_single;
    };

    const std::string mode::remove_all{"remove_all_replicas"};
    const std::string mode::trim_single{"trim_single_replica"};

    int remove_data_object(
          int                _api_index
        , rsComm_t*          _comm
        , const std::string& _user_name
        , const std::string& _object_path
        , const std::string& _source_resource)
    {
        dataObjInp_t obj_inp{};
        rstrcpy(obj_inp.objPath, _object_path.c_str(), sizeof(obj_inp.objPath));
        addKeyVal(&obj_inp.condInput, RESC_NAME_KW, _source_resource.c_str());
        addKeyVal(&obj_inp.condInput, COPIES_KW, "1");
        if(_comm->clientUser.authInfo.authFlag >= LOCAL_PRIV_USER_AUTH) {
            addKeyVal(&obj_inp.condInput, ADMIN_KW, "true" );
        }

        auto trim_fcn = [&](auto& comm) {
            return irods::server_api_call(_api_index, &comm, &obj_inp);
        };

        return irods::exec_as_user(*_comm, _user_name, trim_fcn);

    } // remove_data_object

    irods::error data_retention_policy(const pe::context& ctx)
    {
        pe::configuration_manager cfg_mgr{ctx.instance_name, ctx.configuration};

        std::string mode{}, user_name{}, object_path{}, source_resource{}, attribute{};

        // query processor invocation
        if(ctx.parameters.is_array()) {
            std::string tmp_coll_name{}, tmp_data_name{};

            std::tie(user_name, tmp_coll_name, tmp_data_name, source_resource) =
                irods::extract_array_parameters<4, std::string>(ctx.parameters);

            using fsp = irods::experimental::filesystem::path;

            object_path = (fsp{tmp_coll_name} / fsp{tmp_data_name}).string();
        }
        else {
            std::string tmp_dst_resc;

            // event handler or direct call invocation
            std::tie(user_name, object_path, source_resource, tmp_dst_resc) =
                irods::extract_dataobj_inp_parameters(
                      ctx.parameters
                    , irods::tag_last_resc);
        }

        auto err = SUCCESS();

        std::tie(err, attribute) = cfg_mgr.get_value(
                                         "attribute"
                                       , "irods::retention::preserve_replicas");

        auto comm = ctx.rei->rsComm;

        // if preserve_replicas is true, there is no work to do
        auto [preserve_replicas, unit] = irods::get_metadata_for_resource(
                                               comm
                                             , attribute
                                             , source_resource);
        if("true" == preserve_replicas) {
            return SUCCESS();
        }

        std::tie(err, mode) = cfg_mgr.get_value("mode", "");
        if(!err.ok()) {
            return err;
        }

        std::vector<std::string> src_resc_vec{};
        std::tie(err, src_resc_vec) = cfg_mgr.get_value("source_resource_list", src_resc_vec);
        if(!err.ok()) {
            src_resc_vec.push_back(source_resource);
        }

        const auto api_idx = mode::trim_single == mode
                             ? DATA_OBJ_TRIM_AN
                             : DATA_OBJ_UNLINK_AN;

        for(const auto& src : src_resc_vec) {
            if(src == source_resource) {
                const auto ret = remove_data_object(
                                       api_idx
                                     , comm
                                     , user_name
                                     , object_path
                                     , source_resource);
                if(ret < 0) {
                    return ERROR(
                               ret,
                               boost::format("failed to trim [%s] from [%s]")
                               % object_path
                               % source_resource);
                }
            }
        }

        return SUCCESS();

    } // data_retention_policy

} // namespace

const char usage[] = R"(
{
    "id": "file:///var/lib/irods/configuration_schemas/v3/policy_engine_usage.json",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "description": ""
        "input_interfaces": [
            {
                "name" : "event_handler-collection_modified",
                "description" : "",
                "json_schema" : ""
            },
            {
                "name" :  "event_handler-data_object_modified",
                "description" : "",
                "json_schema" : ""
            },
            {
                "name" :  "event_handler-metadata_modified",
                "description" : "",
                "json_schema" : ""
            },
            {
                "name" :  "event_handler-user_modified",
                "description" : "",
                "json_schema" : ""
            },
            {
                "name" :  "event_handler-resource_modified",
                "description" : "",
                "json_schema" : ""
            },
            {
                "name" :  "direct_invocation",
                "description" : "",
                "json_schema" : ""
            },
            {
                "name" :  "query_results"
                "description" : "",
                "json_schema" : ""
            },
        ],
    "output_json_for_validation" : ""
}
)";

extern "C"
pe::plugin_pointer_type plugin_factory(
      const std::string& _plugin_name
    , const std::string&) {

    return pe::make(
                 _plugin_name
               , "irods_policy_data_retention"
               , usage
               , data_retention_policy);

} // plugin_factory
