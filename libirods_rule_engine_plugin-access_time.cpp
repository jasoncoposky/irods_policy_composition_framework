
#include "policy_engine.hpp"

#include "filesystem.hpp"

#include "rsModAVUMetadata.hpp"
#include "rsOpenCollection.hpp"
#include "rsReadCollection.hpp"
#include "rsCloseCollection.hpp"

namespace {
    void update_access_time_for_data_object(
          rsComm_t*          _comm
        , const std::string& _logical_path
        , const std::string& _attribute) {

        auto ts = std::to_string(std::time(nullptr));
        modAVUMetadataInp_t avuOp{
            "set",
            "-d",
            const_cast<char*>(_logical_path.c_str()),
            const_cast<char*>(_attribute.c_str()),
            const_cast<char*>(ts.c_str()),
            ""};

        auto status = rsModAVUMetadata(_comm, &avuOp);
        if(status < 0) {
            THROW(
                status,
                boost::format("failed to set access time for [%s]") %
                _logical_path);
        }
    } // update_access_time_for_data_object

    void apply_access_time_to_collection(
          rsComm_t*          _comm
        , int                _handle
        , const std::string& _attribute)
    {
        collEnt_t* coll_ent{nullptr};
        int err = rsReadCollection(_comm, &_handle, &coll_ent);
        while(err >= 0) {
            if(DATA_OBJ_T == coll_ent->objType) {
                using fsp = irods::experimental::filesystem::path;
                auto  lp  = fsp{coll_ent->collName} / fsp{coll_ent->dataName};
                update_access_time_for_data_object(_comm, lp.string(), _attribute);
            }
            else if(COLL_OBJ_T == coll_ent->objType) {
                collInp_t coll_inp;
                memset(&coll_inp, 0, sizeof(coll_inp));
                rstrcpy(
                    coll_inp.collName,
                    coll_ent->collName,
                    MAX_NAME_LEN);
                int handle = rsOpenCollection(_comm, &coll_inp);
                apply_access_time_to_collection(_comm, handle, _attribute);
                rsCloseCollection(_comm, &handle);
            }

            err = rsReadCollection(_comm, &_handle, &coll_ent);
        } // while
    } // apply_access_time_to_collection

    namespace pe = irods::policy_engine;

    void access_time_policy(const pe::context& ctx)
    {
        auto comm = ctx.rei->rsComm;

        auto cond_input = ctx.parameters["cond_input"];
        bool collection_operation{!cond_input.empty() && !cond_input[COLLECTION_KW].empty()};

        std::string attribute{"irods::access_time"};
        if(!ctx.configuration.empty() &&
           !ctx.configuration["attribute"].empty()) {
            attribute = ctx.configuration["attribute"];
        }

        std::string obj_path{ctx.parameters["obj_path"]};
        if(obj_path.empty()) {
            THROW(
                SYS_INVALID_INPUT_PARAM,
                "missing object path parameter");
        }

        if(!collection_operation) {
            update_access_time_for_data_object(comm, obj_path, attribute);
        }
        else {
            // register a collection
            collInp_t coll_inp;
            memset(&coll_inp, 0, sizeof(coll_inp));
            rstrcpy(
                  coll_inp.collName
                , obj_path.c_str()
                , MAX_NAME_LEN);
            int handle = rsOpenCollection(comm, &coll_inp);
            if(handle < 0) {
                THROW(
                    handle,
                    boost::format("failed to open collection [%s]") %
                    obj_path);
            }

            apply_access_time_to_collection(comm, handle, attribute);
        }
    } // access_time_policy

} // namespace

extern "C"
pe::plugin_pointer_type plugin_factory(
      const std::string& _plugin_name
    , const std::string&) {
    return pe::make(
                 _plugin_name
               , "irods_policy_access_time"
               , access_time_policy);
} // plugin_factory
