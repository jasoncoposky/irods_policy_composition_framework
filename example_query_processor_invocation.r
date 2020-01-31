{
	"policy" : "irods_policy_enqueue_rule",
        "delay_conditions" : "<PLUSET>1s</PLUSET>",
	"payload" : {
	    "policy" : "irods_policy_execute_rule",
            "payload" : {
	        "policy_to_invoke" : "irods_policy_query_processor",
                "policy_enforcement_point" : "pep_api_nopes",
                "event_name" : "CREATE",
                "parameters" : {
                    "query_string" : "SELECT COLL_NAME, DATA_NAME WHERE COLL_NAME like '/tempZone/home/rods%'",
                    "query_limit" : 10,
                    "query_type" : "general",
                    "number_of_threads" : 4,
                    "policy_to_invoke" : "irods_policy_engine_example"
                 }
             }
        }
}
INPUT null
OUTPUT ruleExecOut

