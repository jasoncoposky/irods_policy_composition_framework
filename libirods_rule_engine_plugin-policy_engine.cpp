
#include "policy_engine.hpp"

namespace pe = irods::policy_engine;

void example_policy(const pe::context& ctx)
{
    //  struct context {
    //      ruleExecInfo_t* rei{};
    //      std::string     instance_name{};
    //      std::string     policy_name{};
    //      json            parameters{};
    //      json            configuration{};
    //  }; // struct context
    rodsLog(
          LOG_NOTICE
        , "[%s]::[%s]"
        , ctx.instance_name.c_str()
        , ctx.policy_name.c_str());
} // example_policy

extern "C"
pe::plugin_pointer_type plugin_factory(
      const std::string& _plugin_name
    , const std::string&) {

    return pe::make(_plugin_name, "irods_policy_engine_example", example_policy);

} // plugin_factory
