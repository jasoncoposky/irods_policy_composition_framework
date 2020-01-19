#ifndef EVENT_HANDLER_DATA_OBJECT_MODIFIED_CONFIGURATION_HPP
#define EVENT_HANDLER_DATA_OBJECT_MODIFIED_CONFIGURATION_HPP

#include <string>
#include <vector>
#include "rcMisc.h"

namespace irods {
    struct event_handler_data_object_modified_configuration {
        const std::string policy_to_invoke_configuration{"policies_to_invoke"};
        std::vector<std::string> policies_to_invoke;
        const std::string instance_name{};
        explicit event_handler_data_object_modified_configuration(const std::string&);
    };
} // namespace irods

#endif // EVENT_HANDLER_DATA_OBJECT_MODIFIED_CONFIGURATION_HPP
