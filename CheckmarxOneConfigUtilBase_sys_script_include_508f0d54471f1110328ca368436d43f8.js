var CheckmarxOneConfigUtilBase = Class.create();
CheckmarxOneConfigUtilBase.prototype = {
    initialize: function() {},

    testCredentials: function(config, uniqueId) {
        var errorMessage = "";
        var resultObj = {};
        var result = "true";
        try {
            if (!config)
                return {
                    "result": "false",
                    "errorMessage": gs.getMessage("CheckmarxOne configuration not found.")
                };
            var response = new x_chec3_chexone.CheckmarxOneUtil().getProject(config.getValue("integration_instance"));
            var implConfig = new GlideRecord("sn_sec_int_impl_config");
        } catch (ex) {
            result = false;
            if (null != ex.message && 'undefined' != ex.message && ex.message.indexOf('Credential validation failed due to missing Permissions') != -1)
                errorMessage = ex.message;
            else
                errorMessage = gs.getMessage("Credential validation failed!");
            gs.warn("Failed to validate Checkmarx credentials!  Reason: {0}", ex);
        } finally {
            resultObj = {
                "result": result,
                "error": errorMessage,
            };
        }
        return resultObj;
    },

    saveInstanceParams: function(sys_id) {
        var gr = new GlideRecord("x_chec3_chexone_checkmarxone_configuration");
        if (gr.get(sys_id)) {
            var instance = gr.getValue("integration_instance");
            var implConfig = new GlideRecord("sn_sec_int_impl_config");
            implConfig.addQuery("implementation", instance);
            implConfig.query();
            while (implConfig.next()) {
                var configName = implConfig.getDisplayValue("configuration");
                var configVal = gr.getValue(configName);
                if (configVal == null)
                    configVal = "";
                if (implConfig.configuration.elem_type == "boolean")
                    implConfig.setValue("value", configVal === "1");
                else
                    implConfig.setValue("value", configVal);
                implConfig.update();
            }

            var newconfig = {
                "client_secret": gr.client_secret.getDecryptedValue(),
                "client_id": gr.getValue("client_id"),
                "tenant": gr.getValue("tenant"),
                "checkmarxone_api_base_url": gr.getValue("checkmarxone_api_base_url"),
                "checkmarxone_server_url": gr.getValue("checkmarxone_server_url"),
                "include_first_detection_date": gr.getValue("include_first_detection_date") === "1",
                "include_only_similarity_id": gr.getValue("include_only_similarity_id") === "1",
                "import_sca": gr.getValue("import_sca") === "1",
                "import_sast": gr.getValue("import_sast") === "1",
                "import_kics": gr.getValue("import_kics") === "1",
                "include_container_security": gr.getValue("include_container_security") === "1",
                "exclude_dev_and_test_dependencies": gr.getValue("exclude_dev_and_test_dependencies") === "1",
                "triaging_in_snow": gr.getValue("triaging_in_snow") === "1",
                "vulnerability_threshold_level": gr.getValue("vulnerability_threshold_level"),
                "scan_synchronization": gr.getValue("scan_synchronization"),
                "access_token": gr.access_token.getDecryptedValue(),
                "sync_only_primary_branch": gr.getValue("sync_only_primary_branch") === "1",
                "list_projects": gr.getValue("list_of_project_id_s"),
                "result_states": gr.getValue("result_states"),
                "link": gr.getValue("link"),
                "project_filter_by_name": gr.getValue("project_filter_by_name"),
                "filter_project": gr.getValue("filter_project"),
                "severity": gr.getValue("severity"),
                "scan_type": gs.nil(gr.getValue("scan_type")) ? "" : gr.getValue("scan_type"),
            };

            new sn_sec_int.Implementation().setConfiguration(instance, newconfig);
            return true;
        }
        return false;
    },

    type: 'CheckmarxOneConfigUtilBase'
};