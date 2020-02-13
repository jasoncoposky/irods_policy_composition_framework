
#include "policy_engine.hpp"

#include "storage_tiering.hpp"

namespace pe = irods::policy_engine;

namespace {

    irods::error storage_tiering_policy(const pe::context& ctx)
    {
        if(ctx.parameters.empty()) {
            return ERROR(
                       SYS_INVALID_INPUT_PARAM,
                       boost::format("[%s] parameters are empty")
                       % ctx.policy_name);
        }

        std::vector<std::string> tier_groups;

        if(ctx.parameters.is_array()) {
            tier_groups = ctx.parameters.get<std::vector<std::string>>();
        }
        else {
            if(ctx.parameters.find("tier_groups") == ctx.parameters.end()) {
                return ERROR(
                           SYS_INVALID_INPUT_PARAM,
                           boost::format("[%s] tier groups are not defined")
                           % ctx.policy_name);
            }

            tier_groups = ctx.parameters["tier_groups"].get<std::vector<std::string>>();
        }

        irods::storage_tiering st{ctx.rei, ctx.instance_name};

        for(auto& g : tier_groups) {
rodsLog(LOG_NOTICE, "Applying Policy for group [%s]", g.c_str());
            st.apply_policy_for_tier_group(g);
        }

        return SUCCESS();

    } // storage_tiering_policy

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
               , "irods_policy_storage_tiering"
               , usage
               , storage_tiering_policy);

} // plugin_factory
