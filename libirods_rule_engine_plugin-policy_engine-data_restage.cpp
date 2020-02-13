
#include "policy_engine.hpp"

#include "storage_tiering.hpp"

namespace pe = irods::policy_engine;

namespace {

    irods::error data_restage_policy(const pe::context& ctx)
    {
        std::string user_name{}, object_path{}, source_resource{};

        // query processor invocation
        if(ctx.parameters.is_array()) {
            using fsp = irods::experimental::filesystem::path;

            std::string tmp_coll_name{}, tmp_data_name{};

            std::tie(tmp_coll_name, tmp_data_name, source_resource) =
                irods::extract_array_parameters<3, std::string>(ctx.parameters);

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

        irods::storage_tiering st{ctx.rei, ctx.instance_name};
        st.migrate_object_to_minimum_restage_tier(
              object_path
            , user_name
            , source_resource);

        return SUCCESS();

    } // data_restage_policy

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
               , "irods_policy_data_restage"
               , usage
               , data_restage_policy);

} // plugin_factory
