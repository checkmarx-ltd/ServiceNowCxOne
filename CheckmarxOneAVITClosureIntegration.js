var CheckmarxOneAVITClosureIntegration = Class.create();
CheckmarxOneAVITClosureIntegration.prototype = Object.extendsObject(sn_vul.ApplicationVulnerabilityIntegrationBase, {

    UTIL: new x_chec3_chexone.CheckmarxOneUtil(),
    MSG: "CheckmarxOneAVITClosureIntegration",
    INTEGRATION_ID: 'e5dffb5c47575110328ca368436d436b', // constant integration filter for Checkmarx Integration

    retrieveData: function() {
        var params = this._getParameters(this.PROCESS.getValue('parameters'));
        var response = ""; // Initialize response variable

        if (params.run) {
            var jsonString = Object.keys(params.run)[0]; // Get the first key from run object.Example: "{\"scanId\":\"227791e7-d442-432d-88b2-2aa5fa0bdb01\",\"scanbranch\":\"dependabot/maven/org.springframework.boot-spring-boot-starter-parent-3.5.3\",\"appId\":\"f46b19d5-8ed0-4cd2-8ba6-1b8234db6d8f\",\"engines\":\"SecretDetection,CS,IaC,sast,sca,containers,kics,apisec,microengines\"}":

            // Convert string to object
            var obj = JSON.parse(jsonString);

            // Access individual fields
            var scanId = obj.scanId;
            var scanbranch = obj.scanbranch;
            var appId = obj.appId;
            var engines = obj.engines;

            try {
                response = this._getLatestScansXMLReport(appId, scanbranch, scanId, engines);

            } catch (err) {
                gs.error(this.MSG + " retrieveData : Error while retrieving the data. Skipping appId: " +
                    appId + ", scanId: " + scanId + " Error: " + err);
                response = "<latestscanreport><xml><scans></scans></xml></latestscanreport>";
            }
        }

        if (!response) {
            response = '<latestscanreport><xml><scans></scans></xml></latestscanreport>';
        }

        params = this._serializeParameters(this._nextParameters(params));
        this.setNextRunParameters(params);

        // Save delta_start_time if no more runs left
        if (!params.run) {
            this.INTEGRATION.setValue('delta_start_time', new GlideDateTime());
            this.INTEGRATION.update();
            this.hasMoreData(false);
        } else {
            this.hasMoreData(true);
        }

        return {
            contents: new GlideSysAttachment().write(this.PROCESS, this.FILENAME, "xml", response),
            contentType: "sys_attachment",
            extension: "xml"
        };
    },

    //Creates XML summary for given scan Id


    _getLatestScansXMLReport: function(appId, scanbranch, scanId, engines) {
        try {
            var latestScanRootNodeStart = '<latestscanreport><xml id="checkmarx"><scans>';
            var latestScanRootNodeEnd = '</scans></xml></latestscanreport>';

            var scanXml = '<scan>' +
                '<id><![CDATA[' + scanId + ']]></id>' +
                '<app_id><![CDATA[' + appId + ']]></app_id>' +
                '<branch><![CDATA[' + scanbranch + ']]></branch>' +
                '<engines><![CDATA[' + engines + ']]></engines>' +
                '</scan>';

            var finalXml = latestScanRootNodeStart + scanXml + latestScanRootNodeEnd;

            return finalXml;

        } catch (ex) {
            gs.error(this.MSG + 'Error in _getLatestScansXMLReport: ' + ex.message);
        }
    },


    // Gets the integration parameters as a map
    _getParameters: function(parameters) {
        var params = {
            run: null,
            remaining: {}
        };
        var offsetId = '';
        var app_list = [];
        var projectIdsByLastScanDate = [];
        try {
            if (parameters) {
                params = JSON.parse(parameters);
                if (params.latest) {
                    var latest = new GlideDateTime();
                    latest.setValue(params.latest);
                    params.latest = latest;
                    this.LATEST = latest;
                }
            } else {
                var results = [];
                var config = this.UTIL._getConfig(this.IMPLEMENTATION);
                var closureDeltaStartTime = this._getThirdIntegrationDeltaDate();
                var scan_synchronization = config.scan_synchronization.toString();
                if (scan_synchronization == 'latest scan of primary branch') {
                    results = this._getLatestScanFromPrimaryBranch(closureDeltaStartTime);
                } else if (scan_synchronization == 'latest scan from each branch') {
                    results = this._getLatestScanFromEachBranch(closureDeltaStartTime);
                } else if (scan_synchronization == 'latest scan across all branches') {
                    results = this._getLatestScanAcrossBranches(closureDeltaStartTime);
                }
                for (var i = 0; i < results.length; i++) {
                    var item = results[i];
                    var scanId = item.scanId;
                    // all scan objects in key and ScanId in value
                    params.remaining[JSON.stringify(item)] = scanId;

                }
                params = this._nextParameters(params);
                if (params.run) {
                    this.PROCESS.setValue('parameters', JSON.stringify(this._serializeParameters(params)));
                    this.PROCESS.update();
                }
            }
        } catch (err) {
            gs.error(this.MSG + " _getParameters : Error while getting the integration parameters." + err);
        }
        return params;
    },
    /**
     * Parses the branch name from the Tags field
     */
    _getBranchFromTags: function(tags) {
        if (tags != null && tags != '') {
            var match = tags.match(/Branch:\s*([^|]*)/);
            return match ? String(match[1] || '').trim() : '.unknown';
        }

    },

    /**
     * Builds a standardized scan object from the scan summary record
     */
    _buildScanObject: function(gr) {
        var appReleaseGr = gr.application_release.getRefRecord();

        // REASON: All data points are now sourced from the two local ServiceNow records.
        var appReleaseId = appReleaseGr.getValue('source_app_id');
        return {
            scanId: gr.getValue('source_sdlc_status'),
            scanbranch: this._getBranchFromTags(gr.getValue('tags')),
            appId: appReleaseId,
            engines: gr.getValue('policy'),

        };
    },

    /**
     * Retrieves all unique application_release.source_app_id values since closureDeltaStartTime
     * Filters only those belonging to a specific integration
     */
    _getUniqueProjectIds: function(closureDeltaStartTime) {
        var appSet = {};
        var apps = [];
        var gr = new GlideRecord('sn_vul_app_vul_scan_summary');
        gr.addEncodedQuery('integration=' + this.INTEGRATION_ID + '^last_scan_date>=javascript:gs.dateGenerate' + closureDeltaStartTime);
        gr.query();
        while (gr.next()) {
            var appId = gr.getValue('application_release');
            if (appId && !appSet[appId]) {
                appSet[appId] = true;
                apps.push(appId);
            }
        }
        return apps;
    },
    /**
     * Scenario 1: Latest scan across all branches per project
     */
    _getLatestScanAcrossBranches: function(closureDeltaStartTime) {
        var results = [];
        var appIds = this._getUniqueProjectIds(closureDeltaStartTime);

        for (var i = 0; i < appIds.length; i++) {
            var appId = appIds[i];
            var gr = new GlideRecord('sn_vul_app_vul_scan_summary');
            gr.addEncodedQuery('application_release=' + appId + '^integration=' + this.INTEGRATION_ID + '^last_scan_date>=javascript:gs.dateGenerate' + closureDeltaStartTime);
            gr.orderByDesc('last_scan_date');
            gr.setLimit(1);
            gr.query();

            if (gr.next()) {
                results.push(this._buildScanObject(gr));
            }
        }
        return results;
    },

    /**
     * Scenario 2: Latest scan from primary branch per project; fallback to latest if none found
     */
    _getLatestScanFromPrimaryBranch: function(closureDeltaStartTime) {
        var results = [];
        var appIds = this._getUniqueProjectIds(closureDeltaStartTime);

        for (var i = 0; i < appIds.length; i++) {
            var appId = appIds[i];
            var matched = false;
            var gr = new GlideRecord('sn_vul_app_vul_scan_summary');
            gr.addEncodedQuery('application_release=' + appId + '^integration=' + this.INTEGRATION_ID + '^last_scan_date>=javascript:gs.dateGenerate' + closureDeltaStartTime);
            gr.orderByDesc('last_scan_date');
            gr.query();

            while (gr.next()) {
                var branch = this._getBranchFromTags(gr.getValue('tags'));
                // REASON: Joins to the Discovered Application table to get project-level details locally,
                // avoiding an API call to /api/projects. This leverages the work of the AppListIntegration.
                var appReleaseGr = gr.application_release.getRefRecord();
                var primaryBranch = appReleaseGr.getValue('source_app_guid') || '';
                if (branch == primaryBranch) {
                    var scanObj = this._buildScanObject(gr);
                    scanObj.primaryBranch = primaryBranch;
                    results.push(scanObj);
                    matched = true;
                    break;
                }
            }
            if (!matched) {
                gr.setLimit(1);
                if (gr.next()) {
                    var fallbackObj = this._buildScanObject(gr);
                    fallbackObj.primaryBranch = primaryBranch;
                    results.push(fallbackObj);
                }
            }
        }

        return results;
    },

    /**
     * Scenario 3: Latest scan from each unique branch per project
     */
    _getLatestScanFromEachBranch: function(closureDeltaStartTime) {
        var results = [];
        var appIds = this._getUniqueProjectIds(closureDeltaStartTime);

        for (var i = 0; i < appIds.length; i++) {
            var appId = appIds[i];
            var seenBranches = {};
            var gr = new GlideRecord('sn_vul_app_vul_scan_summary');
            gr.addEncodedQuery('application_release=' + appId + '^integration=' + this.INTEGRATION_ID + '^last_scan_date>=javascript:gs.dateGenerate' + closureDeltaStartTime);
            gr.orderByDesc('last_scan_date');
            gr.query();

            while (gr.next()) {
                var branch = this._getBranchFromTags(gr.getValue('tags'));
                if (!seenBranches[branch]) {
                    var scanObj = this._buildScanObject(gr);
                    results.push(scanObj);
                    seenBranches[branch] = true;
                }
            }
        }

        return results;
    },

    _serializeParameters: function(params) {
        if (params.latest)
            params.latest = params.latest.getValue();
        else
            delete params.latest;
        return params;
    },


    _nextParameters: function(params) {
        params.run = null;
        var keys = Object.keys(params.remaining);
        if (keys.length) {
            params.run = {};
            var key = keys[0];
            params.run[key] = params.remaining[key]; // Just assign the string
            delete params.remaining[key]; // Remove key after processing
        }

        params.latest = this.LATEST;
        return params;
    },


    //To get Delta Date from third Integration
    _getThirdIntegrationDeltaDate: function() {

        var config = this.UTIL._getConfig(this.IMPLEMENTATION);
        var apibaseurl = config.checkmarxone_api_base_url;
        var third_integeration_delta_start_time = config.delta_start_time;
        var gdt = (typeof third_integeration_delta_start_time === 'string') ? new GlideDateTime(third_integeration_delta_start_time) : third_integeration_delta_start_time;

        var datePart = gdt.getDate().getByFormat('yyyy-MM-dd');
        var timePart = gdt.getTime().getByFormat('HH:mm:ss');

        var closureDeltaStartTime = "('" + datePart + "','" + timePart + "')";
        return closureDeltaStartTime;
    },

    type: 'CheckmarxOneAVITClosureIntegration'
});