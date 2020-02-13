
#include "policy_engine.hpp"

namespace pe = irods::policy_engine;

namespace {
    using invoke_policy_type = std::function<void(ruleExecInfo_t*, const std::string&, std::list<boost::any>)>;

    void apply_data_replication_policy(
          ruleExecInfo_t*    _rei
        , const std::string& _parameters) {
        std::list<boost::any> args;
        args.push_back(boost::any(_parameters));
        args.push_back(boost::any(std::string{}));
        irods::invoke_policy(_rei, "irods_policy_data_replication", args);

    } // apply_data_replication_policy

    void apply_data_verification_policy(
          ruleExecInfo_t*    _rei
        , const std::string& _parameters)
    {
        std::list<boost::any> args;
        args.push_back(boost::any(_parameters));
        args.push_back(boost::any(std::string{}));
        irods::invoke_policy(_rei, "irods_policy_data_verification", args);

    } // apply_data_verification_policy

    void apply_data_retention_policy(
          ruleExecInfo_t*    _rei
        , const std::string& _parameters) {
        std::list<boost::any> args;
        args.push_back(boost::any(_parameters));
        args.push_back(boost::any(std::string{}));
        irods::invoke_policy(_rei, "irods_policy_data_retention", args);

    } // apply_data_retention_policy

    irods::error data_movement_policy(const pe::context& ctx)
    {

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
                    , irods::tag_first_resc);
        }

        nlohmann::json params = {
              { "user_name", user_name }
            , { "object_path", object_path }
            , { "source_resource", source_resource }
            , { "destination_resource", destination_resource }
        };

        apply_data_replication_policy(
              ctx.rei
            , ctx.parameters.dump());

        apply_data_verification_policy(
              ctx.rei
            , ctx.parameters.dump());

        apply_data_retention_policy(
              ctx.rei
            , ctx.parameters.dump());

        return SUCCESS();

    } // data_movement_policy

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
               , "irods_policy_data_movement"
               , usage
               , data_movement_policy);

} // plugin_factory
