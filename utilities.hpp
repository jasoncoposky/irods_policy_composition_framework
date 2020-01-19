
#include "irods_re_plugin.hpp"
#include "irods_exception.hpp"
#include "rodsError.h"

namespace irods {
    auto any_to_string(boost::any&);
    void exception_to_rerror(const irods::exception&, rError_t&);
    void exception_to_rerror(const int, const char*, rError_t&);
    void invoke_policy(ruleExecInfo_t*, const std::string&, std::list<boost::any>);
} // namespace irods
