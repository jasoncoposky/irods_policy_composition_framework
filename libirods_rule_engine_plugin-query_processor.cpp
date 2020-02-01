
#include "policy_engine.hpp"

#include "irods_query.hpp"
#include "thread_pool.hpp"
#include "query_processor.hpp"

#include "json.hpp"

namespace {
    namespace pe = irods::policy_engine;

    void query_processor_policy(const pe::context& ctx)
    {
        try {

            std::string query_string{ctx.parameters.at("query_string")};
            int         query_limit{ctx.parameters.at("query_limit")};
            auto        query_type{irods::query<rsComm_t>::convert_string_to_query_type(ctx.parameters.at("query_type"))};
            std::string policy_to_invoke{ctx.parameters.at("policy_to_invoke")};
            int number_of_threads{4};
            if(!ctx.parameters["number_of_threads"].empty()) {
                number_of_threads = ctx.parameters["number_of_threads"];
            }

            using json       = nlohmann::json;
            using result_row = irods::query_processor<rsComm_t>::result_row;

            auto job = [&](const result_row& _results) {
                auto res_arr = json::array();
                for(auto& r : _results) {
                    res_arr.push_back(r);
                }

                std::list<boost::any> arguments;
                arguments.push_back(boost::any(res_arr.dump()));
                arguments.push_back(boost::any(ctx.configuration.dump()));
                irods::invoke_policy(ctx.rei, policy_to_invoke, arguments);
            }; // job

            irods::thread_pool thread_pool{number_of_threads};
            irods::query_processor<rsComm_t> qp(query_string, job, query_limit, query_type);
            auto future = qp.execute(thread_pool, *ctx.rei->rsComm);
            auto errors = future.get();
            if(errors.size() > 0) {
                for(auto& e : errors) {
                    rodsLog(
                        LOG_ERROR,
                        "scheduling failed [%d]::[%s]",
                        std::get<0>(e),
                        std::get<1>(e).c_str());
                }

                THROW(
                    SYS_INVALID_OPR_TYPE,
                    boost::format(
                    "scheduling failed for [%d] objects for query [%s]")
                    % errors.size()
                    % query_string.c_str());
            }

        }
        catch(const irods::exception& e) {
            if(CAT_NO_ROWS_FOUND == e.code()) {
                // if nothing of interest is found, thats not an error
            }
            else {
                irods::log(e);
                irods::exception_to_rerror(
                    e, ctx.rei->rsComm->rError);
            }
        }

    } // query_processor_policy

} // namespace

extern "C"
pe::plugin_pointer_type plugin_factory(
      const std::string& _plugin_name
    , const std::string&)
{
    return pe::make(
            _plugin_name,
            "irods_policy_query_processor",
            query_processor_policy);
} // plugin_factory
