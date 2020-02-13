{
	"policy" : "irods_policy_enqueue_rule",
        "delay_conditions" : "",
	"payload" : {
	    "policy" : "irods_policy_execute_rule",
            "payload" : {
	        "policy_to_invoke" : "irods_policy_storage_tiering",
                "parameters" : {
                    "tier_groups" : ["example_group" ],
                    "log_errors" : "true"
                 },
                 "configuration" : {
                 }
             }
        }
}
INPUT null
OUTPUT ruleExecOut

