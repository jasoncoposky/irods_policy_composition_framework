

#include <functional>
#include "rcConnect.h"
#include "irods_at_scope_exit.hpp"
#include "irods_stacktrace.hpp"

namespace irods {
    template <typename Function>
    int exec_as_user(rsComm_t& _comm, const std::string& _user_name, Function _func)
    {
        if(_user_name.empty()) {
            THROW(
                SYS_INVALID_INPUT_PARAM,
                "user name is empty");
        }

        auto& user = _comm.clientUser;

        const std::string old_user_name = user.userName;

        rstrcpy(user.userName, _user_name.data(), NAME_LEN);

        irods::at_scope_exit<std::function<void()>> at_scope_exit{[&user, &old_user_name] {
            rstrcpy(user.userName, old_user_name.c_str(), MAX_NAME_LEN);
        }};

        return _func(_comm);
    } // exec_as_user

} // namespace irods
