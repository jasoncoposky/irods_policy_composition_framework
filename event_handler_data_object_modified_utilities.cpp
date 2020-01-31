
#include "event_handler_data_object_modified_utilities.hpp"

#include "irods_resource_backport.hpp"

#include "rcMisc.h"
#include "objDesc.hpp"

#include "boost/lexical_cast.hpp"

// Persistent L1 File Descriptor Table
extern l1desc_t L1desc[NUM_L1_DESC];

namespace irods {
    auto get_index_and_json_from_obj_inp(const dataObjInp_t* _inp) -> std::tuple<int, std::string>{
        int l1_idx{};
        dataObjInfo_t* obj_info{};
        for(const auto& l1 : L1desc) {
            if(FD_INUSE != l1.inuseFlag) {
                continue;
            }
            if(!strcmp(l1.dataObjInp->objPath, _inp->objPath)) {
                obj_info = l1.dataObjInfo;
                l1_idx = &l1 - L1desc;
            }
        }

        if(nullptr == obj_info) {
            THROW(
                SYS_INVALID_INPUT_PARAM,
                "no object found");
        }
        auto jobj = serialize_dataObjInp_to_json(*_inp);
        return std::make_tuple(l1_idx, jobj.dump());
    } // get_index_and_resource_from_obj_inp

    auto serialize_keyValPair_to_json(const keyValPair_t& _kvp) -> json {
        json j;
        if(_kvp.len > 0) {
            for(int i = 0; i < _kvp.len; ++i) {
               if(_kvp.keyWord && _kvp.keyWord[i]) {
                    if(_kvp.value && _kvp.value[i]) {
                        j[_kvp.keyWord[i]] = _kvp.value[i];
                    }
                    else {
                        j[_kvp.keyWord[i]] = "empty_value";
                    }
                }
            }
        } else {
            j["keyValPair_t"] = "nullptr";
        }

        return j;
    } // serialize_keyValPair_to_json

    auto serialize_dataObjInp_to_json(const dataObjInp_t& _inp) -> json {
        json j;
        j["obj_path"]    = _inp.objPath;
        j["create_mode"] = boost::lexical_cast<std::string>(_inp.createMode);
        j["open_flags"]  = boost::lexical_cast<std::string>(_inp.openFlags);
        j["offset"]      = boost::lexical_cast<std::string>(_inp.offset);
        j["data_size"]   = boost::lexical_cast<std::string>(_inp.dataSize);
        j["num_threads"] = boost::lexical_cast<std::string>(_inp.numThreads);
        j["opr_type"]    = boost::lexical_cast<std::string>(_inp.oprType);
        j["cond_input"]  = serialize_keyValPair_to_json(_inp.condInput);

        return j;
    } // seralize_dataObjInp_to_json


} // namespace irods

