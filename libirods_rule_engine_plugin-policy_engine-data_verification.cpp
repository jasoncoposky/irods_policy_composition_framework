
#include "policy_engine.hpp"
#include "exec_as_user.hpp"
#include "configuration_manager.hpp"
#include "data_verification_utilities.hpp"

namespace pe = irods::policy_engine;

namespace {
    irods::error data_verification_policy(const pe::context& ctx)
    {
        irods::configuration_manager cfg_mgr{ctx.instance_name, ctx.configuration};

        std::string user_name{}, object_path{}, source_resource{}, destination_resource{}, verification_type{}, unit{};

        if(ctx.parameters.is_array()) {
            using fsp = irods::experimental::filesystem::path;

            std::string tmp_coll_name{}, tmp_data_name{};

            std::tie(tmp_coll_name, tmp_data_name, source_resource, destination_resource) =
                irods::extract_array_parameters<4, std::string>(ctx.parameters);

            object_path = (fsp{tmp_coll_name} / fsp{tmp_data_name}).string();
        }
        else {
            // event handler or direct call invocation
            std::tie(user_name, object_path, source_resource, destination_resource) =
                irods::extract_dataobj_inp_parameters(
                      ctx.parameters
                    , irods::tag_last_resc);
        }

        auto [err, attribute] = cfg_mgr.get_value("attribute", "irods::verification::type");

        auto comm = ctx.rei->rsComm;

        std::tie(verification_type, unit) = irods::get_metadata_for_resource(comm, attribute, destination_resource);

        auto verif_fcn = [&](auto& comm) {
            return irods::verify_replica_for_destination_resource(
                         &comm
                       , verification_type
                       , object_path
                       , source_resource
                       , destination_resource);};

        auto verified = irods::exec_as_user(*comm, user_name, verif_fcn);

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
