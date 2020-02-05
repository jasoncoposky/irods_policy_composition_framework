
#include "policy_engine.hpp"

#include "storage_tiering.hpp"

namespace pe = irods::policy_engine;

namespace {

    irods::error data_restage_policy(const pe::context& ctx)
    {
        std::string object_path{}, source_resource{};

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
            std::tie(object_path, source_resource, tmp_dst_resc) = irods::extract_dataobj_inp_parameters(
                                                                                 ctx.parameters
                                                                               , irods::tag_last_resc);
        }
        irods::storage_tiering st{ctx.rei, ctx.instance_name};
        st.migrate_object_to_minimum_restage_tier(
              object_path
            , ctx.rei->rsComm->clientUser.userName
            , source_resource);

        return SUCCESS();

    } // data_restage_policy

} // namespace

extern "C"
pe::plugin_pointer_type plugin_factory(
      const std::string& _plugin_name
    , const std::string&) {

    return pe::make(_plugin_name, "irods_policy_data_restage", data_restage_policy);

} // plugin_factory
