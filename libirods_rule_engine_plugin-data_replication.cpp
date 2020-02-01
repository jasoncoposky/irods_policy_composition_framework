
#include "policy_engine.hpp"
#include "filesystem.hpp"

#include "irods_hierarchy_parser.hpp"
#include "irods_server_api_call.hpp"

#include "rsDataObjRepl.hpp"
#include "physPath.hpp"
#include "apiNumber.h"

namespace {
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

    namespace pe = irods::policy_engine;

    void replication_policy(const pe::context ctx)
    {
        std::string object_path{}, source_resource{}, destination_resource{};

        // output from query processor is an array of results
        if(ctx.parameters.is_array()) {
            using fsp = irods::experimental::filesystem::path;

            fsp coll{ctx.parameters[0]};
            fsp data{ctx.parameters[1]};

            auto p = coll / data;
            object_path = p.string();
            source_resource = ctx.parameters[2];
        }
        else {
            object_path = ctx.parameters["obj_path"];

            auto param_source_resource = ctx.parameters["source_resource"];
            if(!param_source_resource.empty()) {
                source_resource = param_source_resource;
            }
            else {
                std::string resc_hier{};
                auto param_resc_hier = ctx.parameters["cond_input"]["resc_hier"];
                if(param_resc_hier.empty()) {
                    THROW(
                        SYS_INVALID_INPUT_PARAM,
                        boost::format("%s - source_resource or resc_hier not provided")
                        % ctx.policy_name);
                }

                resc_hier = param_resc_hier;
                irods::hierarchy_parser parser(resc_hier);
                source_resource = parser.first_resc();
            }

            auto param_destination_resource = ctx.parameters["destination_resource"];
            if(!param_destination_resource.empty()) {
                destination_resource = param_destination_resource;
            }
        }

        auto comm = ctx.rei->rsComm;

        if(!destination_resource.empty()) {
            replicate_object_to_resource(
                comm
                , object_path
                , source_resource
                , destination_resource);
        }
        else {
            if(ctx.configuration.empty()) {
                THROW(
                    SYS_INVALID_INPUT_PARAM,
                    boost::format("%s - destination_resource is empty and configuration is not provided")
                    % ctx.policy_name);
            }

            auto param_destination_resource = ctx.configuration["destination_resource"];
            if(!param_destination_resource.empty()) {
                destination_resource = param_destination_resource;
                replicate_object_to_resource(
                      comm
                    , object_path
                    , source_resource
                    , destination_resource);
            }
            else {
                auto src_dst_map{ctx.configuration.at("source_to_destination_map")};
                if(src_dst_map.empty()) {
                    THROW(
                        SYS_INVALID_INPUT_PARAM,
                        boost::format("%s - destination_resource or source_to_destination_map not provided")
                        % ctx.policy_name);
                }
                auto dst_resc_arr{src_dst_map.at(source_resource)};
                auto destination_resources = dst_resc_arr.get<std::vector<std::string>>();
                for( auto& dest : destination_resources) {
                    replicate_object_to_resource(
                          comm
                        , object_path
                        , source_resource
                        , dest);
                }
            }
        }
    } // replication_policy
} // namespace

extern "C"
pe::plugin_pointer_type plugin_factory(
      const std::string& _plugin_name
    , const std::string&)
{
    return pe::make(
             _plugin_name
            , "irods_policy_data_replication"
            , replication_policy);
} // plugin_factory
