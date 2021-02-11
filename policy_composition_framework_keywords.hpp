#ifndef IRODS_POLICY_COMPOSITION_FRAMEWORK_KEYWORDS_HPP
#define IRODS_POLICY_COMPOSITION_FRAMEWORK_KEYWORDS_HPP

#include <string>

namespace irods::policy_composition::keywords {
    // metadata
    const std::string set{"set"};
    const std::string add{"add"};
    const std::string remove{"rm"};
    const std::string value{"value"};
    const std::string units{"units"};
    const std::string entity{"entity"};
    const std::string metadata{"metadata"};
    const std::string operation{"operation"};
    const std::string attribute{"attribute"};
    const std::string entity_type{"entity_type"};
    const std::string conditional_metadata{"conditional_metadata"};

    // entity_type
    const std::string user{"user"};
    const std::string resource{"resource"};
    const std::string collection{"collection"};
    const std::string data_object{"data_object"};

    // conditional behavior
    const std::string recursive{"recursive"};
    const std::string conditional{"conditional"};
    const std::string metadata_exists{"metadata_exists"};
    const std::string metadata_applied{"metadata_applied"};

    // framework
    const std::string comm{"comm"};
    const std::string event{"event"};
    const std::string events{"events"};
    const std::string user_name{"user_name"};
    const std::string entity_types{"entity_types"};
    const std::string logical_path{"logical_path"};
    const std::string source_resource{"source_resource"};
    const std::string destination_resource{"destination_resource"};
    const std::string active_policy_clauses{"active_policy_clauses"};
    const std::string policy_enforcement_point{"policy_enforcement_point"};

    const std::string log_errors{"log_errors"};
    const std::string parameters{"parameters"};
    const std::string query_results{"query_results"};
    const std::string configuration{"configuration"};
    const std::string policy_to_invoke{"policy_to_invoke"};
    const std::string policies_to_invoke{"policies_to_invoke"};

} // namespace irods::policy_composition::keywords

#endif // IRODS_POLICY_COMPOSITION_FRAMEWORK_KEYWORDS_HPP
