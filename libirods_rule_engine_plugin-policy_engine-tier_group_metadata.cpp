
#include "policy_engine.hpp"
#include "filesystem.hpp"
#include "storage_tiering.hpp"

namespace pe = irods::policy_engine;

namespace {
    auto get_group_name_for_data_object(
          rsComm_t*           _comm
        , const std::string& _object_path
        , const std::string& _resource_name
        , const std::string& _attribute)
    {
        irods::experimental::filesystem::path p{_object_path};
        std::string coll_name = p.parent_path().string();
        std::string data_name = p.object_name().string();

        auto query_str{boost::str(boost::format(
             "SELECT META_RESC_ATTR_VALUE, order(DATA_REPL_NUM) WHERE COLL_NAME = '%s' AND DATA_NAME = '%s' AND RESC_NAME = '%s' AND META_RESC_ATTR_NAME = '%s'")
                % coll_name
                % data_name
                % _resource_name
                % _attribute)};
        irods::query qobj{_comm, query_str, 1};
        if(qobj.size() <= 0) {
            return std::string{};
        }

        return qobj.front()[0];

    } // get_group_name_for_data_object

    irods::error tier_group_metadata_policy(const pe::context& ctx)
    {

        auto comm = ctx.rei->rsComm;

        std::string user_name{}, object_path{}, source_resource{}, destination_resource{};

        // query processor invocation
        if(ctx.parameters.is_array()) {
            using fsp = irods::experimental::filesystem::path;

            std::string tmp_coll_name{}, tmp_data_name{};

            std::tie(tmp_coll_name, tmp_data_name, source_resource) =
                irods::extract_array_parameters<3, std::string>(ctx.parameters);

            object_path = (fsp{tmp_coll_name} / fsp{tmp_data_name}).string();
        }
        else {
            // event handler or direct call invocation
            std::tie(user_name, object_path, source_resource, destination_resource) =
                irods::extract_dataobj_inp_parameters(
                      ctx.parameters
                    , irods::tag_last_resc);
        }

        auto group_name = get_group_name_for_data_object(
                                comm
                              , object_path
                              , source_resource
                              , "irods::storage_tiering::group");

        irods::storage_tiering st{ctx.rei, ctx.instance_name};
        st.apply_tier_group_metadata_to_object(
              group_name
            , object_path
            , user_name
            , destination_resource);

        return SUCCESS();

    } // tier_group_metadata_policy

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
               , "irods_policy_tier_group_metadata"
               , usage
               , tier_group_metadata_policy);

} // plugin_factory
