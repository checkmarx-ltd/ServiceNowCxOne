function clientValidation() {
    g_form.clearMessages();
    if (!g_form.getValue("client_id") && !g_form.getValue("client_secret")) {
        g_form.addErrorMessage(getMessage("Enter Client ID and Client Key."));
        return false;
    } else if (!g_form.getValue("client_id")) {
        g_form.addErrorMessage(getMessage("Enter Client ID."));
        return false;
    } else if (!g_form.getValue("client_secret")) {
        g_form.addErrorMessage(getMessage("Enter Client Key."));
        return false;
    } else if (!g_form.getValue("checkmarxone_api_base_url")) {
        g_form.addErrorMessage(getMessage("Enter CheckmarxOne API Base URL"));
        return false;
    } else if (!g_form.getValue("checkmarxone_server_url")) {
        g_form.addErrorMessage(getMessage("Enter CheckmarxOne AccessControl Base URL"));
        return false;
    } else if (g_form.getValue("filter_project") == "by_Id" && g_form.getValue("list_of_project_id_s").length == 0) {
        g_form.addErrorMessage(getMessage("Project Id field is blank, Please enter valid project Ids needs to be filtered seperated by ; to proceed"));
        return false;
    } else if (g_form.getValue("filter_project") == "by_name" && g_form.getValue("project_filter_by_name").length == 0) {
        g_form.addErrorMessage(getMessage("Project Name field is blank, Please enter valid project name needs to be filtered seperated by ; to proceed"));
        return false;
    } else if (g_form.getValue("filter_project") == "by_Id" && g_form.getValue("list_of_project_id_s").split(";").length > 1000) {
        g_form.addWarningMessage(getMessage("Project id's list is too long."));
        return false;
    } else if (g_form.getValue("other_result_states").split(";").length > 1000) {
        g_form.addWarningMessage(getMessage("Custom State's list is too long."));
        return false;
    } else if (g_form.getValue("filter_project") == "by_name" && g_form.getValue("project_filter_by_name").split(";").length > 1000) {
        g_form.addWarningMessage(getMessage("Project Name's list is too long."));
        return false;
    } else if (!g_form.getValue("severity")) {
        g_form.addErrorMessage(getMessage("Select at least one Severity to proceed"));
        return false;
    }

    if (g_form.getValue("import_sast") == "false" && g_form.getValue("import_sca") == "false" && g_form.getValue("import_kics") == "false" &&
        g_form.getValue("include_ossf_scorecard") == "false" && g_form.getValue("include_secret_detection") == "false" && g_form.getValue("include_api_security") == "false") {
        g_form.addWarningMessage(getMessage("Select SCA, SAST, IaC, OSSF Scorecard, API Security, Secret Detection to proceed."));
        return false;
    }

    if (g_form.getValue("include_api_security") == 'true' && g_form.getValue("import_sast") == "false") {
        g_form.addWarningMessage(getMessage('Select SAST also if API Security is Selected.'));
        return false;
    }
    if (g_form.getValue("other_result_states") && g_form.getValue("other_result_states").match(/[^a-zA-Z0-9;]/)) {
        g_form.addWarningMessage(getMessage("Allow only English alphabetic characters and numbers in custom state name"));
        return false;
    }
    gsftSubmit(null, g_form.getFormElement(), 'Checkmarxone_configuration_save');
}

if (typeof window == 'undefined')
    serverSide();

function serverSide() {
    current.doRedirect = true;
    current.update();
    action.setRedirectURL(current);

    // Handle Other result state
    var resultStates = current.getValue("result_states") || "";
    resultStates = resultStates.split(";").map(function (state) {
        return state.trim();
    }).join(",");
    if (resultStates.includes("OTHER")) {
        var otherResultStates = current.getValue("other_result_states") || "";
        var otherStatesArray = otherResultStates.split(";").map(function (state) {
            return state.trim().replace(/\s+/g, "_").toUpperCase();
        });
        resultStates = resultStates.replace("OTHER", otherStatesArray.join(","));
        resultStates = resultStates.split(";").filter(function (state, index, self) {
            return self.indexOf(state) === index;
        }).join(",");
        current.setValue("result_states", resultStates);
    }
    current.update();

    var instance = current.getValue("integration_instance");
    var implConfig = new GlideRecord("sn_sec_int_impl_config");
    implConfig.addQuery("implementation", instance);
    implConfig.query();
    while (implConfig.next()) {
        var configName = implConfig.getDisplayValue("configuration");
        var configVal = implConfig.getDisplayValue("value");
        if ((configName == "limit" || configName == "log_level")) {
            current.setValue(configName, configVal);
        }
    }
    current.update();

    if (new CheckmarxOneConfigUtil().saveInstanceParams(current.getUniqueValue())) {
        var config = new GlideRecord("x_chec3_chexone_checkmarxone_configuration");
        if (config.get(current.getUniqueValue())) {
            var res = new x_chec3_chexone.CheckmarxOneConfigUtil().testCredentials(current, current.getUniqueValue());
            if (res.result == "true") {
                gs.addInfoMessage(gs.getMessage("Checkmarx One validation successful."));
            } else
                gs.addErrorMessage(res.error);
        }
    }
}