var CheckmarxOneDevOpsIntegration = Class.create();
CheckmarxOneDevOpsIntegration.prototype = Object.extendsObject(sn_vul.DevOpsVulnerabilityIntegrationBase, {
    UTIL: new x_chec3_chexone.CheckmarxOneUtil(),

    retrieveData: function() {
        try {
            var body = null;
            var processParams = this._getParameters();
            processParams = this._validateAndUpdateParams(processParams);


            //validate scan status, if results are not ready defer it to next run
            if (processParams.scanId && processParams.scanStatus == "false") {
                this._updateDevOpsIntegrationRunState([processParams.sysId], 'new', 'success', gs.getMessage('Scan is still in progress, deferring to next run.'));
                return;
            }

            var response = this.UTIL.getLastScanInfo(this.IMPLEMENTATION, processParams.appId, processParams.scanId);
            body = JSON.parse(response.getBody());

            if (gs.nil(body))
                throw gs.getMessage("Invalid API response for process: {}", [this.PROCESS.getDisplayValue()]);



            body.totalVulnerabilities = this.UTIL.getTotal_SAST_KICS_Vulcount(this.IMPLEMENTATION, body.id);
            body.Query = JSON.stringify(this.UTIL.processQueryData(this.IMPLEMENTATION, body.id));


            var fileName = this.integrationGr.name + "_" + new GlideDateTime().toString() + ".json";
            return {
                contents: new GlideSysAttachment().write(this.PROCESS, fileName, "json", JSON.stringify(body)),
                contentType: "sys_attachment",
                extension: "json"
            };
        } catch (err) {
            gs.error(err);
            if (this.RUN_SYS_ID) {
                this._updateDevOpsIntegrationRunState([this.RUN_SYS_ID], 'complete', 'failed', err);
            }
        }
    },

    _validateAndUpdateParams: function(processParams) {
        var appId = processParams.projectId;
        var appName = processParams.projectName;
        var scanId = processParams.scanId;

        if (gs.nil(appId) && gs.nil(appName)) {
            throw gs.getMessage('Missing application info for fetching Scan summary details of process: {0}',
                [this.PROCESS.getDisplayValue()]);
        }

        var applicationInfo = this._fetchProjectInfo(appId, appName);

        if (gs.nil(applicationInfo)) {
            throw gs.getMessage("Application Id not found for process: {0}.", [this.PROCESS.getDisplayValue()]);
        }

        processParams.applicationId = appId = applicationInfo;

        if (gs.nil(scanId)) {
            scanId = this._fetchScanId(appId);
        }
        if (!gs.nil(scanId)) {
            processParams.scanId = scanId;
            processParams.scanStatus = this._fetchScanStatus(appId, scanId);
        }
        return processParams;
    },

    _fetchProjectInfo: function(appId, appName) {
        var queryParams = {};
        var projectId = '';
        if (!gs.nil(appId)) {
            queryParams.app_id = appId;
            var responseByid = this.UTIL.getProjectById(this.IMPLEMENTATION, appId);
            projectId = responseByid.id.toString();

        } else if (!gs.nil(appName)) {
            queryParams.app_name = encodeURIComponent(appName);
            var responseByname = this.UTIL.getProjectByName(this.IMPLEMENTATION, queryParams.app_name);
            for (var item in responseByname.projects) {
                projectId = responseByname.projects[item].id;
            }
        }
        if (projectId.length == 0 || projectId == '') {
            throw gs.getMessage("Application details could not be found for the process: {0}", [this.PROCESS.getDisplayValue()]);


        } else {
            return projectId;
        }


    },

    _fetchScanId: function(appId) {
        var resp = this.UTIL.getLastScan(this.IMPLEMENTATION, appId);
        var jsonLastScanSummResp = JSON.parse(resp.getBody());

        if (jsonLastScanSummResp.scans) {
            for (var item in jsonLastScanSummResp.scans) {
                return jsonLastScanSummResp.scans[item].id;
            }
        }
        return null;
    },


    _fetchScanStatus: function(appId, scanId) {
        var resp = this.UTIL.getLastScanInfo(this.IMPLEMENTATION, appId, scanId);
        var jsonLastScanSummResp = JSON.parse(resp.getBody());

        if (jsonLastScanSummResp.scans) {
            for (var item in jsonLastScanSummResp.scans) {
                return jsonLastScanSummResp.scans[item].status;
            }
        }
        return null;
    },

    type: 'CheckmarxOneDevOpsIntegration'
});