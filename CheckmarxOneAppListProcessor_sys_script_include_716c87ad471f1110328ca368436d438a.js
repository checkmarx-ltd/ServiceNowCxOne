var CheckmarxOneAppListProcessor = Class.create();
CheckmarxOneAppListProcessor.prototype = Object.extendsObject(sn_vul.ApplicationVulnerabilityImportProcessorBase, {
    /*
     * Converts an xml string of application information objects into javascript objects
     *    passed individually to the VR AppVul API
     */
    MSG: 'CheckmarxOne AppListProcessor:',
    UTIL: new x_chec3_chexone.CheckmarxOneUtil(),

    process: function(attachment) {
        if (!attachment) {
            gs.warn(gs.getMessage('CheckmarxOneAppListProcessor: Called with no attachment'));
            return;
        }
        try {
            this.UTIL.validateXML(new GlideSysAttachment().getContent(attachment), 'error');
            //Parsing the Project List attachment
            var appDoc = new XMLDocument2();
            appDoc.parseXML(new GlideSysAttachment().getContent(attachment));
            var listNode = appDoc.getNode("/appInfoList/xml/projects");
            var iter = listNode.getChildNodeIterator();

        } catch (ex) {
            gs.error(this.MSG + "Error occurred while validating or parsing the XML: " + ex);
            throw ex;
        }
        var errorProcess = '';
        while (iter.hasNext()) {
            try {
                var appNode = iter.next();
                var attributes = appNode.getAttributes();
                var applicationId = '';
                var appId;
                var projectTags = '';
                var primaryBranch = '';
                var infoObj = {};

                var childIter = appNode.getChildNodeIterator();
                var projectTagsFlag = 'false';
                var primaryBranchFlag = 'false';
                while (childIter.hasNext) {
                    var childNode = childIter.next();
                    if (childNode.getNodeName() == "projectTags") {
                        projectTags = childNode.getTextContent();
                        projectTagsFlag = 'true';
                    }
                    if (childNode.getNodeName() == "primaryBranch") {
                        primaryBranch = childNode.getTextContent();
                        primaryBranchFlag = 'true';
                    }
                    if (projectTagsFlag == 'true' && primaryBranchFlag == 'true')
                        break;
                }
                if (appNode.getAttribute('applicationIds') && appNode.getAttribute('applicationIds') != {})
                    infoObj[gs.getMessage("Application Id ")] = appNode.getAttribute('applicationIds').toString();

                if (null != primaryBranch && '' != primaryBranch)
                    infoObj[gs.getMessage("Primary Branch ")] = primaryBranch.toString();

                if (infoObj == {})
                    infoObj = "";

                //map attributes from Checkmarx into the servicenow expected format'
                var appObj = {
                    source_app_id: attributes.id,
                    app_name: appNode.getLastChild().getTextContent().toString(),
                    apm_app_id: projectTags,
                    source_assigned_teams: attributes.groups,
                    description: 'created at' + attributes.createdAt,
                    source_additional_info: JSON.stringify(infoObj),
                    source_app_guid: primaryBranch.toString()

                };
                //Updating the project information in ServiceNow table
                var result = this.AVR_API.createOrUpdateApp(appObj);
                if (result != null) {
                    if (result.inserted)
                        this.import_counts.inserted++;
                    else if (result.updated)
                        this.import_counts.updated++;
                    else if (result.unchanged)
                        this.import_counts.unchanged++;
                }

            } catch (ex) {
                errorMessage = gs.getMessage("Error in retriving data for app list integration!");
                gs.error(this.MSG + "errorMessage " + ex);
                errorProcess += " | " + ex.getMessage();
            }
        }

        if (!gs.nil(errorProcess))
            gs.error(this.MSG + "All errors that occurred while processing project lists: " + errorProcess);
        this.completeProcess(this.integrationProcessGr, this.import_counts);
    },

    type: 'CheckmarxOneAppListProcessor'
});