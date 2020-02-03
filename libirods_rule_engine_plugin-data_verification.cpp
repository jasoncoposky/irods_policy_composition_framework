
#include "policy_engine.hpp"
#include "plugin_configuration_json.hpp"
#include "data_verification_utilities.hpp"

namespace pe = irods::policy_engine;

namespace {
    irods::error data_verification_policy(const pe::context& ctx)
    {
        std::string object_path{}, source_resource{}, destination_resource{}, attribute{};

        if(ctx.parameters.is_array()) {
            using fsp = irods::experimental::filesystem::path;

            std::string tmp_coll_name{}, tmp_data_name{};

            std::tie(tmp_coll_name, tmp_data_name, source_resource, destination_resource) =
                irods::extract_array_parameters<4, std::string>(ctx.parameters);

            object_path = (fsp{tmp_coll_name} / fsp{tmp_data_name}).string();
        }
        else {
            // event handler or direct call invocation
            std::tie(object_path, source_resource, destination_resource) = irods::extract_dataobj_inp_parameters(
                                                                                 ctx.parameters
                                                                               , irods::tag_last_resc);
        }

        auto comm = ctx.rei->rsComm;

        irods::plugin_configuration_json cfg{ctx.instance_name};

        attribute = irods::extract_object_parameter<std::string>("attribute", cfg.plugin_configuration);
        if(attribute.empty()) {
            attribute = "irods::verification::type";
        }

        auto [verification_type, unit] = irods::get_metadata_for_resource(comm, attribute, destination_resource);

        auto verified = irods::verify_replica_for_destination_resource(
                              comm
                            , verification_type
                            , object_path
                            , source_resource
                            , destination_resource);

        if(verified) {
            return SUCCESS();
        }
        else {
            return ERROR(
                    UNMATCHED_KEY_OR_INDEX,
                    boost::format("verification [%s] failed from [%s] to [%s]")
                        % verification_type
                        % source_resource
                        % destination_resource);
        }

    } // data_verification_policy

} // namespace

extern "C"
pe::plugin_pointer_type plugin_factory(
      const std::string& _plugin_name
    , const std::string&) {

    return pe::make(_plugin_name, "irods_policy_data_verification", data_verification_policy);

} // plugin_factory
