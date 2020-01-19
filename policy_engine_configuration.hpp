#ifndef STORAGE_TIERING_CONFIGURATION_HPP
#define STORAGE_TIERING_CONFIGURATION_HPP

#include <string>
#include "rcMisc.h"

namespace irods {
    struct policy_engine_configuration {
        const std::string example_metadata_attribute_configuration{"example_metadata_attribute_configuration"};
        std::string example_metadata_attribute{"irods::example_attribute"};

        const std::string example_key_configuration{"example_key_configuration"};
        std::string example_value_configuration{"example_value_configuration"};

        int example_integer_default_configuration{42};

        const std::string instance_name{};
        explicit policy_engine_configuration(const std::string&);
    };
} // namespace irods

#endif // STORAGE_TIERING_CONFIGURATION_HPP
