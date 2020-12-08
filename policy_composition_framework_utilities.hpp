
#include "irods_re_plugin.hpp"
#include "irods_exception.hpp"

#include "rodsError.h"
#include "generalAdmin.h"

#include "json.hpp"

#include <string>
#include <map>

namespace irods::policy_composition {

    // clang-format off
    using json           = nlohmann::json;
    using event_map_type = std::map<std::string, std::string>;
    using arguments_type = std::list<boost::any>;
    // clang-format on

    auto any_to_string(boost::any&);
    void exception_to_rerror(const irods::exception&, rError_t&);
    void exception_to_rerror(const int, const char*, rError_t&);
    auto collapse_error_stack(rError_t& _error);
    void invoke_policy(ruleExecInfo_t*, const std::string&, std::list<boost::any>&);

    auto advance_or_throw(const arguments_type&, const uint32_t) -> arguments_type::const_iterator;
    auto pep_to_event(const event_map_type&, const std::string&) -> std::string;
    auto get_index_and_json_from_obj_inp(const dataObjInp_t*) -> std::tuple<int, json>;
    auto serialize_generalAdminInp_to_json(const generalAdminInp_t&) -> json;
    auto serialize_keyValPair_to_json(const keyValPair_t&) -> json;
    auto serialize_collInp_to_json(const collInp_t&) -> json;
    auto serialize_dataObjInp_to_json(const dataObjInp_t&) -> json;
    auto serialize_openedDataObjInp_to_json(const openedDataObjInp_t& _inp) -> json;
    auto serialize_rsComm_to_json(rsComm_t*) -> json;
    auto invoke_policies_for_event(ruleExecInfo_t*, const std::string&, const std::string&, const json&, const json&) -> void;
    auto evaluate_metadata_conditional(const json&, const json&) -> bool;
} // namespace irods
