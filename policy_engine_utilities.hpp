
#include "irods_re_plugin.hpp"
#include "irods_exception.hpp"
#include "irods_hierarchy_parser.hpp"
#include "irods_stacktrace.hpp"
#include "rodsError.h"

#define IRODS_QUERY_ENABLE_SERVER_SIDE_API
#include "irods_query.hpp"

#define IRODS_FILESYSTEM_ENABLE_SERVER_SIDE_API
#include "filesystem.hpp"

#include "json.hpp"

namespace irods {

    auto any_to_string(boost::any&);
    void exception_to_rerror(const irods::exception&, rError_t&);
    void exception_to_rerror(const int, const char*, rError_t&);
    auto collapse_error_stack(rError_t& _error);
    void invoke_policy(ruleExecInfo_t*, const std::string&, std::list<boost::any>&);

} // namespace irods
