var CheckmarxOneAppVulItemIntegration = Class.create();
CheckmarxOneAppVulItemIntegration.prototype = Object.extendsObject(sn_vul.ApplicationVulnerabilityIntegrationBase, {

    UTIL: new x_chec3_chexone.CheckmarxOneUtil(),
    MSG: "CheckmarxOneAppVulItemIntegration",

    retrieveData: function () {
        var response = "<null/>";
        var apiSecResponse = "<null/>";
        try {
            var params = this._getParameters(this.PROCESS.getValue('parameters'));

            if (params.run != null) {
                var integration_run = this.PROCESS.integration_run;
                var applicationIds = [];
                var applicationIdsStr = '';
                var engines = [];
                var engine = '';
                var scanDetailedRootNodeEnd = "</scanResults>";
                var result = {};
                var scans = Object.keys(params.run)[0];

                // Ensure input is a string and split on `;`
                scans.toString().split(';').forEach(function (pair) {
                    var parts = pair.split('=').map(function (part) {
                        return String(part || '').trim();
                    });

                    // Make sure there's a key-value pair
                    if (parts.length === 2) {
                        var key = parts[0];
                        var value = parts[1];
                        result[key] = value;
                    }
                });

                // Extract individual values
                var scanId = result["scanId"];
                var appname = result["appname"];
                var branch = result["scanbranch"];
                var appId = result["appId"];
                var lastscandate = result["last_scan_date"];
                engines = result.engines;
                applicationIds += result["applicationIds"];
                var primaryBranch = result["primaryBranch"];
                var config = this.UTIL._getConfig(this.IMPLEMENTATION);
                var resultState = config.result_states;
                var resultStateFilter = false;
                if (null != resultState && '' != resultState) {
                    resultStateFilter = true;
                    var result_state_array = this.UTIL.getResultStateFromUI(this.IMPLEMENTATION);
                }
                var ui_severity = config.severity;
                if (null != ui_severity && '' != ui_severity) {
                    var severity = config.severity;
                }

                if (applicationIds && applicationIds.length > 0) {
                    applicationIdsStr = applicationIds.toString();
                }
                var offset = params.run[Object.keys(params.run)[0]];

            }
            var xml_response = '';
            if (params.run) {
                //   scanId, offset
                if (offset > 0) {
                    response = this.getDetailedReport(scanId, params.run[Object.keys(params.run)[0]], lastscandate, appname, branch, appId, applicationIdsStr, engines, severity, resultStateFilter, result_state_array);
                    if (response == "<null/>") {
                        xml_response = '<scanResults><Results></Results><ApiSecResults></ApiSecResults></scanResults>';
                    } else {
                        xml_response = response + '<Results></Results>' + scanDetailedRootNodeEnd;
                    }

                } else {
                    var process = this._getLatestProcessRecord();
                    if (process == 'false' && process != '') {
                        var trial = 0;
                        while (trial < 100) {
                            if (trial < 10) {
                                this.customSleep(3000);
                            } else {
                                this.customSleep(5000);
                            }
                            var status = this._getLatestProcessRecord();
                            if (status == 'true' && process != '') {
                                break;
                            }
                            trial++;
                        }
                    }

                    apiSecResponse = this.getApiSecReport(scanId, params.run[Object.keys(params.run)[0]], lastscandate, appname, branch, appId, applicationIdsStr, engines);

                    if (apiSecResponse == "<null/>") {
                        xml_response = '<scanResults><Results></Results><ApiSecResults></ApiSecResults></scanResults>';
                    } else {
                        xml_response = apiSecResponse + scanDetailedRootNodeEnd;
                    }
                }

            }

        } catch (err) {
            gs.error(this.MSG + " retrieveData : Error occured while getting report. Skipping buildId: " + scanId + " with error: " + err);
            xml_response = '<scanResults><Results></Results><ApiSecResults></ApiSecResults></scanResults>';
        }
        if (xml_response == "") {
            xml_response = '<scanResults><Results></Results><ApiSecResults></ApiSecResults></scanResults>';
        }
        params = this._serializeParameters(this._nextParameters(params));
        this.setNextRunParameters(params);

        //Saving delta_start_time
        if (!params.run) {
            var latest = this.LATEST ? this.LATEST : '';
            this.INTEGRATION.setValue('delta_start_time', latest);
            this.INTEGRATION.update();
            this.hasMoreData(false);
        } else
            this.hasMoreData(true);
        return {
            contents: new GlideSysAttachment().write(this.PROCESS, this.FILENAME, "xml", xml_response),
            contentType: "sys_attachment",
            extension: "xml"
        };
    },

    getDetailedReport: function (scanId, offset, lastscandate, appname, branch, appId, applicationIdsStr, engines, severity, resultStateFilter, result_state_array) {
        try {
            var includesca = this.UTIL.importScaFlaw(this.IMPLEMENTATION);
            var includesast = this.UTIL.importSastFlaw(this.IMPLEMENTATION);
            var includekics = this.UTIL.importKicsFlaw(this.IMPLEMENTATION);
            var includeContainerSecurity = this.UTIL.importContainerSecurityFlaw(this.IMPLEMENTATION);
            var includeSecretDetection = this.UTIL.importSecretDetectionFlaw(this.IMPLEMENTATION);
            var includeScoreCard = this.UTIL.importScoreCardFlaw(this.IMPLEMENTATION);
            var includeApiSecurity = this.UTIL.importApiSecurityFlaw(this.IMPLEMENTATION);
            var config = this.UTIL._getConfig(this.IMPLEMENTATION);
            var apibaseurl = config.checkmarxone_api_base_url;
            var basicContent = '<scanResults app_id="' + this.UTIL.escapeXmlChars(appId) + '"' +
                ' scan_id="' + this.UTIL.escapeXmlChars(scanId) + '"' +
                ' last_scan_date="' + this.UTIL.escapeXmlChars(lastscandate) + '"' +
                ' branch="' + this.UTIL.escapeXmlChars(branch) + '"' +
                ' engine="' + this.UTIL.escapeXmlChars(engines) + '"' +
                '><Results>';
            var SCAscanDetailedAll = '';
            var SASTscanDetailedAll = '';
            // var SASTDeltascanDetailedAll = '';
            var KICSscanDetailedAll = '';
            var conSecScanDetailedAll = '';
            var secretDetectionScanDetailedAll = '';
            var scorecardScanDetailedAll = '';
            var scanDetailedAll = '';
            var line = '';
            var ref = '';
            var notes = '';
            var recommendedVersion = '';
            var location = '';
            var package_unique_id = " ";
            var package_name = " ";
            var cvssScore = " ";
            var cvssVector = " ";
            var newoffset = offset - 1;
            var scan_type = "static";
            var responseLastScanReport = this.UTIL.getVulInfo(this.IMPLEMENTATION, scanId, newoffset, severity);
            var jsonLastScanReportResp = JSON.parse(responseLastScanReport.getBody());
            var configScanType = config.scan_type.toString();



            for (item in jsonLastScanReportResp.results) {
                if (((resultStateFilter == true && (result_state_array.indexOf(jsonLastScanReportResp.results[item].state.toUpperCase()) != -1)) ||
                    resultStateFilter == false)) {
                    if (includesast == true && jsonLastScanReportResp.results[item].type == "sast") {
                        var isSastScanIncluded = 'false';
                        var scanTypeToCheck = '';
                        var sastseverity = jsonLastScanReportResp.results[item].severity;
                        var sast_path = '';
                        var m = 0;
                        for (j in jsonLastScanReportResp.results[item].data.nodes) {
                            if (m < 100) {
                                var full_path = ' path:' + jsonLastScanReportResp.results[item].data.nodes[j].fileName + ' line: ' + jsonLastScanReportResp.results[item].data.nodes[j].line + ' column: ' + jsonLastScanReportResp.results[item].data.nodes[j].column;
                                sast_path += full_path;
                                m++;
                            }
                        }
                        var sastScanUrl = '';

                        if (!jsonLastScanReportResp.results[item].data.resultHash.indexOf('/') == -1) {
                            sastScanUrl = apibaseurl + '/results/' + scanId + '/' + appId + '/sast?result-id=' + encodeURIComponent(jsonLastScanReportResp.results[item].data.resultHash) + '&amp;redirect=true';
                        } else {
                            sastScanUrl = apibaseurl + '/results/' + scanId + '/' + appId + '/sast';
                        }
                        var sastId = jsonLastScanReportResp.results[item].id;
                        SASTscanDetailedAll += '<result id="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].similarityId) + '"' +
                            ' scan_type="' + this.UTIL.escapeXmlChars(scan_type) + '"' +
                            ' sast_id="' + this.UTIL.escapeXmlChars(sastId) + '"' +
                            ' cweId="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].vulnerabilityDetails.cweId) + '"' +
                            ' cweName="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].data.queryName) + '"' +
                            ' category_name="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].data.queryName) + '"' +
                            ' source_severity="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].severity) + '"' +
                            ' package_unique_id="' + this.UTIL.escapeXmlChars(package_unique_id) + '"' +
                            ' package_name="' + this.UTIL.escapeXmlChars(package_name) + '"' +
                            ' location="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].data.nodes[0].fileName) + '"' +
                            ' line_no="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].data.nodes[0].line) + '"' +
                            ' cvssScore="' + this.UTIL.escapeXmlChars(cvssScore) + '"' +
                            ' recommendation="' + this.UTIL.escapeXmlChars(recommendedVersion) + '"' +
                            ' sourcefile="' + this.UTIL.escapeXmlChars(apibaseurl + '/results/' + scanId + '/' + appId + '/sast') + '"' +
                            ' cvssVector="' + this.UTIL.escapeXmlChars(cvssVector) + '"' +
                            ' first_found_date="' + this.UTIL.escapeXmlChars(this.UTIL.parseDate(jsonLastScanReportResp.results[item].firstFoundAt)) + '"' +
                            ' state="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].state) + '"' +
                            ' status="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].status) + '"' +
                            ' app_id="' + this.UTIL.escapeXmlChars(appId) + '"' +
                            ' branch="' + this.UTIL.escapeXmlChars(branch) + '"' +
                            ' last_scan_date="' + this.UTIL.escapeXmlChars(lastscandate) + '"' +
                            ' application_ids="' + this.UTIL.escapeXmlChars(applicationIdsStr) + '"' +
                            ' scan_id="' + this.UTIL.escapeXmlChars('sast' + scanId) + '">' +
                            '<references>' + this.UTIL.escapeCDATA(sast_path) + '</references>' +
                            '<resultHash>' + this.UTIL.escapeCDATA(jsonLastScanReportResp.results[item].data.resultHash) + '</resultHash>' +
                            '<description>' + this.UTIL.escapeCDATA(jsonLastScanReportResp.results[item].description) + '</description>' +
                            '</result>';
                    }

                    if (includesca == true && jsonLastScanReportResp.results[item].type == "sca") {
                        var exploitable_method = '';
                        for (var k in jsonLastScanReportResp.results[item].data.packageData) {
                            var url = jsonLastScanReportResp.results[item].data.packageData[k].url;
                            ref += url + ',  ';
                        }
                        
						var sca_packageID = jsonLastScanReportResp.results[item].data.packageIdentifier;
						recommendedVersion = jsonLastScanReportResp.results[item].data.recommendedVersion;

                        if (jsonLastScanReportResp.results[item].data.exploitableMethods != null) {

                            for (var exp in jsonLastScanReportResp.results[item].data.exploitableMethods) {
                                var exp_path = 'fullName= ' + jsonLastScanReportResp.results[item].data.exploitableMethods[exp].fullName +
                                    ' || SourceFile= ' + jsonLastScanReportResp.results[item].data.exploitableMethods[exp].sourceFile + ';  ';
                            }

                            exploitable_method = 'Exploitable methods: ' + exp_path;
                        }
                        var scaseverity = jsonLastScanReportResp.results[item].severity;
                        SCAscanDetailedAll += '<result id="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].id) + '"' +
                            ' scan_type="sca"' +
                            ' cweId="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].vulnerabilityDetails.cweId) + '"' +
                            ' cweName="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].vulnerabilityDetails.cveName) + '"' +
                            ' cvssScore="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].vulnerabilityDetails.cvssScore) + '"' +
                            ' cvssVector="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].vulnerabilityDetails.cvss.attackVector) + '"' +
                            ' category_name="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].vulnerabilityDetails.cweId) + '"' +
                            ' source_severity="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].severity) + '"' +
                            ' first_found_date="' + this.UTIL.escapeXmlChars(this.UTIL.parseDate(jsonLastScanReportResp.results[item].firstFoundAt)) + '"' +
                            ' state="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].state) + '"' +
                            ' status="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].status) + '"' +
                            ' package_unique_id="' + this.UTIL.escapeXmlChars(sca_packageID) + '"' +
                            ' recommendation="' + this.UTIL.escapeXmlChars(recommendedVersion) + '"' +
                            ' package_name="' + this.UTIL.escapeXmlChars(sca_packageID) + '"' +
                            ' sourcefile="' + this.UTIL.escapeXmlChars(apibaseurl + '/results/' + appId + '/' + scanId + '/sca') + '"' +
                            ' line_no="' + this.UTIL.escapeXmlChars(line) + '"' +
                            ' location="' + this.UTIL.escapeXmlChars(location) + '"' +
                            ' app_id="' + this.UTIL.escapeXmlChars(appId) + '"' +
                            ' branch="' + this.UTIL.escapeXmlChars(branch) + '"' +
                            ' exploitable_method="' + this.UTIL.escapeXmlChars(exploitable_method) + '"' +
                            ' last_scan_date="' + this.UTIL.escapeXmlChars(lastscandate) + '"' +
                            ' application_ids="' + this.UTIL.escapeXmlChars(applicationIdsStr) + '"' +
                            ' scan_id="' + this.UTIL.escapeXmlChars('sca' + scanId) + '">' +
                            '<references>' + this.UTIL.escapeCDATA(ref) + '</references>' +
                            '<description>' + this.UTIL.escapeCDATA(jsonLastScanReportResp.results[item].description) + '</description>' +
                            '</result>';
                    }
                    if (includekics == true && jsonLastScanReportResp.results[item].type == "kics") {
                        var kicsseverity = jsonLastScanReportResp.results[item].severity;

                        var kicsowasp = this._getOWASPTop10(jsonLastScanReportResp.results[item].vulnerabilityDetails.compliances);
                        var kicssans = this._getSANSTop25(jsonLastScanReportResp.results[item].vulnerabilityDetails.compliances);
                        KICSscanDetailedAll += '<result id="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].similarityId) + '"' +
                            ' scan_type="kics"' +
                            ' cweId="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].data.queryId) + '"' +
                            ' cweName="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].data.queryName) + '"' +
                            ' category_name="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].data.queryName) + '"' +
                            ' source_severity="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].severity) + '"' +
                            ' package_unique_id="' + this.UTIL.escapeXmlChars(package_unique_id) + '"' +
                            ' package_name="' + this.UTIL.escapeXmlChars(package_name) + '"' +
                            ' location="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].data.fileName) + '"' +
                            ' line_no="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].data.line) + '"' +
                            ' cvssScore="' + this.UTIL.escapeXmlChars(cvssScore) + '"' +
                            ' recommendation="' + this.UTIL.escapeXmlChars(recommendedVersion) + '"' +
                            ' sourcefile="' + this.UTIL.escapeXmlChars(apibaseurl + '/results/' + scanId + '/' + appId + '/kics') + '"' +
                            ' cvssVector="' + this.UTIL.escapeXmlChars(cvssVector) + '"' +
                            ' first_found_date="' + this.UTIL.escapeXmlChars(this.UTIL.parseDate(jsonLastScanReportResp.results[item].firstFoundAt)) + '"' +
                            ' state="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].state) + '"' +
                            ' status="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].status) + '"' +
                            ' app_id="' + this.UTIL.escapeXmlChars(appId) + '"' +
                            ' branch="' + this.UTIL.escapeXmlChars(branch) + '"' +
                            ' last_scan_date="' + this.UTIL.escapeXmlChars(lastscandate) + '"' +
                            ' OWASPTop10="' + this.UTIL.escapeXmlChars(kicsowasp) + '"' +
                            ' SANSTop25="' + this.UTIL.escapeXmlChars(kicssans) + '"' +
                            ' application_ids="' + this.UTIL.escapeXmlChars(applicationIdsStr) + '"' +
                            ' scan_id="' + this.UTIL.escapeXmlChars('IaC' + scanId) + '">' +
                            '<references>' + this.UTIL.escapeCDATA(notes) + '</references>' +
                            '<description>' + this.UTIL.escapeCDATA(jsonLastScanReportResp.results[item].description) + '</description>' +
                            '</result>';
                    }

                    if (includeContainerSecurity == true && jsonLastScanReportResp.results[item].type == "containers") {
                        var conSecSeverity = jsonLastScanReportResp.results[item].severity;
                        var packageName = jsonLastScanReportResp.results[item].data.packageName + jsonLastScanReportResp.results[item].data.packageVersion;
                        var pathStr = jsonLastScanReportResp.results[item].data.packageName + jsonLastScanReportResp.results[item].data.packageVersion + jsonLastScanReportResp.results[item].data.imageName + jsonLastScanReportResp.results[item].data.imageTag + jsonLastScanReportResp.results[item].data.imageFilePath + jsonLastScanReportResp.results[item].data.imageOrigin;
                        var digest = new GlideDigest();
                        var access_vector = '';
                        var result_hash = '' + digest.getSHA256Base64(pathStr);
                        if (jsonLastScanReportResp.results[item].vulnerabilityDetails.cvss != null && jsonLastScanReportResp.results[item].vulnerabilityDetails.cvss != '') {
                            access_vector = jsonLastScanReportResp.results[item].vulnerabilityDetails.cvss.access_vector;
                        }
                        conSecScanDetailedAll += '<result id="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].similarityId) + '"' +
                            ' scan_type="containers"' +
                            ' cweId="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].vulnerabilityDetails.cweId) + '"' +
                            ' cweName="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].vulnerabilityDetails.cveName) + '"' +
                            ' category_name="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].vulnerabilityDetails.cweId) + '"' +
                            ' source_severity="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].severity) + '"' +
                            ' package_unique_id="' + this.UTIL.escapeXmlChars(packageName) + '"' +
                            ' package_name="' + this.UTIL.escapeXmlChars(packageName) + '"' +
                            ' location="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].data.imageFilePath) + '"' +
                            ' line_no="' + this.UTIL.escapeXmlChars(line) + '"' +
                            ' cvssScore="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].vulnerabilityDetails.cvssScore) + '"' +
                            ' recommendation="' + this.UTIL.escapeXmlChars(recommendedVersion) + '"' +
                            ' sourcefile="' + this.UTIL.escapeXmlChars(apibaseurl + '/container-security-results/' + appId + '/' + scanId + '/results/') + '"' +
                            ' cvssVector="' + this.UTIL.escapeXmlChars(access_vector) + '"' +
                            ' first_found_date="' + this.UTIL.escapeXmlChars(this.UTIL.parseDate(jsonLastScanReportResp.results[item].firstFoundAt)) + '"' +
                            ' state="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].state) + '"' +
                            ' status="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].status) + '"' +
                            ' app_id="' + this.UTIL.escapeXmlChars(appId) + '"' +
                            ' branch="' + this.UTIL.escapeXmlChars(branch) + '"' +
                            ' last_scan_date="' + this.UTIL.escapeXmlChars(lastscandate) + '"' +
                            ' application_ids="' + this.UTIL.escapeXmlChars(applicationIdsStr) + '"' +
                            ' result_hash="' + this.UTIL.escapeXmlChars(result_hash) + '"' +
                            ' scan_id="' + this.UTIL.escapeXmlChars('CS' + scanId) + '">' +
                            '<references>' + this.UTIL.escapeCDATA(notes) + '</references>' +
                            '<description>' + this.UTIL.escapeCDATA(jsonLastScanReportResp.results[item].description) + '</description>' +
                            '</result>';
                    }
                    // secret detection
                    if (includeSecretDetection == true && jsonLastScanReportResp.results[item].type == "sscs-secret-detection") {
                        var secretDetectionSeverity = jsonLastScanReportResp.results[item].severity;
                        secretDetectionScanDetailedAll += '<result id="' +
                            this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].similarityId + '_' + jsonLastScanReportResp.results[item].id) + '"' +
                            ' scan_type="SecretDetection"' +
                            ' cweId="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].id) + '"' +
                            ' cweName=""' +
                            ' category_name="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].data.ruleName) + '"' +
                            ' source_severity="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].severity) + '"' +
                            ' package_unique_id="' + this.UTIL.escapeXmlChars(package_unique_id) + '"' +
                            ' package_name="' + this.UTIL.escapeXmlChars(package_name) + '"' +
                            ' location="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].data.fileName) + '"' +
                            ' line_no="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].data.line) + '"' +
                            ' cvssScore="' + this.UTIL.escapeXmlChars(cvssScore) + '"' +
                            ' recommendation="' + this.UTIL.escapeXmlChars(recommendedVersion) + '"' +
                            ' sourcefile="' + this.UTIL.escapeXmlChars(apibaseurl + '/results/' + scanId + '/' + appId + '/kics') + '"' +
                            ' cvssVector="' + this.UTIL.escapeXmlChars(cvssVector) + '"' +
                            ' first_found_date="' + this.UTIL.escapeXmlChars(this.UTIL.parseDate(jsonLastScanReportResp.results[item].firstFoundAt)) + '"' +
                            ' state="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].state) + '"' +
                            ' status="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].status) + '"' +
                            ' app_id="' + this.UTIL.escapeXmlChars(appId) + '"' +
                            ' branch="' + this.UTIL.escapeXmlChars(branch) + '"' +
                            ' last_scan_date="' + this.UTIL.escapeXmlChars(lastscandate) + '"' +
                            ' application_ids="' + this.UTIL.escapeXmlChars(applicationIdsStr) + '"' +
                            ' scan_id="' + this.UTIL.escapeXmlChars('SecretDetection' + scanId) + '">' +
                            '<source_notes>' + this.UTIL.escapeCDATA(jsonLastScanReportResp.results[item].data.ruleDescription) + '</source_notes>' +
                            '<remediation>' + this.UTIL.escapeCDATA(
                                'Remediation: ' + jsonLastScanReportResp.results[item].data.remediation +
                                ', Remediation link:' + jsonLastScanReportResp.results[item].data.remediationLink +
                                ', Remediation Additional= ' + jsonLastScanReportResp.results[item].data.remediationAdditional
                            ) + '</remediation>' +
                            '<description>' + this.UTIL.escapeCDATA(jsonLastScanReportResp.results[item].description) + '</description>' +
                            '</result>';
                    }


                    // scorecard detection
                    if (includeScoreCard == true && jsonLastScanReportResp.results[item].type == "sscs-scorecard") {
                        var scorecardSeverity = jsonLastScanReportResp.results[item].severity;
                        scorecardScanDetailedAll += '<result id="' +
                            this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].similarityId + '_' + jsonLastScanReportResp.results[item].id) + '"' +
                            ' scan_type="ScoreCard"' +
                            ' cweId="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].id) + '"' +
                            ' cweName=""' +
                            ' category_name="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].data.ruleName) + '"' +
                            ' source_severity="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].severity) + '"' +
                            ' package_unique_id="' + this.UTIL.escapeXmlChars(package_unique_id) + '"' +
                            ' package_name="' + this.UTIL.escapeXmlChars(package_name) + '"' +
                            ' location="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].data.fileName) + '"' +
                            ' line_no="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].data.line) + '"' +
                            ' cvssScore="' + this.UTIL.escapeXmlChars(cvssScore) + '"' +
                            ' recommendation="' + this.UTIL.escapeXmlChars(recommendedVersion) + '"' +
                            ' sourcefile="' + this.UTIL.escapeXmlChars(apibaseurl + '/results/' + scanId + '/' + appId + '/kics') + '"' +
                            ' cvssVector="' + this.UTIL.escapeXmlChars(cvssVector) + '"' +
                            ' first_found_date="' + this.UTIL.escapeXmlChars(this.UTIL.parseDate(jsonLastScanReportResp.results[item].firstFoundAt)) + '"' +
                            ' state="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].state) + '"' +
                            ' status="' + this.UTIL.escapeXmlChars(jsonLastScanReportResp.results[item].status) + '"' +
                            ' app_id="' + this.UTIL.escapeXmlChars(appId) + '"' +
                            ' branch="' + this.UTIL.escapeXmlChars(branch) + '"' +
                            ' last_scan_date="' + this.UTIL.escapeXmlChars(lastscandate) + '"' +
                            ' application_ids="' + this.UTIL.escapeXmlChars(applicationIdsStr) + '"' +
                            ' scan_id="' + this.UTIL.escapeXmlChars('ScoreCard' + scanId) + '">' +
                            '<source_notes>' + this.UTIL.escapeCDATA(jsonLastScanReportResp.results[item].data.ruleDescription) + '</source_notes>' +
                            '<remediation>' + this.UTIL.escapeCDATA(
                                'Remediation: ' + jsonLastScanReportResp.results[item].data.remediation +
                                ', Remediation link:' + jsonLastScanReportResp.results[item].data.remediationLink +
                                ', Remediation Additional= ' + jsonLastScanReportResp.results[item].data.remediationAdditional
                            ) + '</remediation>' +
                            '<description>' + this.UTIL.escapeCDATA(jsonLastScanReportResp.results[item].description) + '</description>' +
                            '</result>';
                    }

                }
            }
            if (includesca == true) {
                scanDetailedAll += SCAscanDetailedAll;
            }
            if (includesast == true) {
                scanDetailedAll += SASTscanDetailedAll;

            }
            if (includekics == true) {
                scanDetailedAll += KICSscanDetailedAll;
            }
            if (includeContainerSecurity == true) {
                scanDetailedAll += conSecScanDetailedAll;
            }
            if (includeScoreCard) {
                scanDetailedAll += scorecardScanDetailedAll;
            }
            if (includeSecretDetection) {
                scanDetailedAll += secretDetectionScanDetailedAll;
            }
        } catch (err) {
            gs.info(this.MSG + " getDetailedReport : Error while getting the detailed report: " + err);
            throw err;
        }
        var reportcontent = basicContent + scanDetailedAll + '</Results>';
        return reportcontent;
    },

    getApiSecReport: function (scanId, offset, lastscandate, appname, branch, appId, applicationIdsStr, engines) {
        try {
            var newoffset = offset - offset * 2;
            var basicContent = '<scanResults app_id="' + this.UTIL.escapeXmlChars(appId) + '"' +
                ' scan_id="' + this.UTIL.escapeXmlChars(scanId) + '"' +
                ' last_scan_date="' + this.UTIL.escapeXmlChars(lastscandate) + '"' +
                ' branch="' + this.UTIL.escapeXmlChars(branch) + '"' +
                '><Results></Results><ApiSecResults>';
            var apiSecScanDetailedAll = '';
            var responseApiSecScanReport = this.UTIL.getApiSecVulInfo(this.IMPLEMENTATION, scanId, newoffset);
            var jsonApiSecScanReportResp = JSON.parse(responseApiSecScanReport.getBody());

            var config = this.UTIL._getConfig(this.IMPLEMENTATION);
            var resultState = config.result_states;
            var resultStateFilter = !!resultState;
            var result_state_array = resultStateFilter ? this.UTIL.getResultStateFromUI(this.IMPLEMENTATION) : [];

            var ui_severity = config.severity;
            var severity_array = this.UTIL.getSeverityFromUI(this.IMPLEMENTATION);

            for (var entry in jsonApiSecScanReportResp.entries) {
                if (((resultStateFilter && result_state_array.includes(jsonApiSecScanReportResp.entries[entry].state)) ||
                    !resultStateFilter) &&
                    severity_array.includes(jsonApiSecScanReportResp.entries[entry].severity.toUpperCase())) {

                    var affectedUrl = jsonApiSecScanReportResp.entries[entry].http_method + " " + jsonApiSecScanReportResp.entries[entry].url;
                    apiSecScanDetailedAll += '<apisec appId="' + this.UTIL.escapeXmlChars(appId) + '"' +
                        ' scanId="' + this.UTIL.escapeXmlChars(scanId) + '"' +
                        ' sast_risk_id="' + this.UTIL.escapeXmlChars(jsonApiSecScanReportResp.entries[entry].sast_risk_id) + '"' +
                        ' affected_url="' + this.UTIL.escapeXmlChars(affectedUrl) + '"/>';
                }
            }
            var reportcontent = basicContent + apiSecScanDetailedAll + '</ApiSecResults>';
            return reportcontent;

        } catch (err) {
            gs.error(this.MSG + " getApiSecReport : Error processing API Security report: " + err);
            throw err;
        }
    },


    //no system function for scoped application like this integration
    customSleep: function (ms) {
        try {
            var endSleep = new GlideDuration().getNumericValue() + ms;
            while (new GlideDuration().getNumericValue() < endSleep) {
                //wait 
            }
        } catch (err) {
            gs.error(this.MSG + " :customSleep :Error in customSleep().");
            throw err;
        }
        return;
    },


    //get Fast Scan Mode value
    _getScanType: function (configId, appId, scanId) {
        var scanResponse = this.UTIL.getScanConfigInfo(configId, appId, scanId);
        var scanType = '';
        for (var item in scanResponse) {
            var key = scanResponse[item].key.toString();
            if (key == 'scan.config.sast.fastScanMode') {
                var fastValue = scanResponse[item].value.toString();
                if (fastValue == 'true') {
                    scanType = 'fastScanMode';
                    break;
                }
            } else if (key == 'scan.config.sast.incremental') {
                var incValue = scanResponse[item].value.toString();
                if (incValue == 'true') {
                    scanType = 'incrementalScan';
                    break;
                }
            }
        }
        if (scanType == '')
            scanType = 'fullScan';

        return scanType;
    },

    // To get information of process, if API security Scanner is selected.
    _getLatestProcessRecord: function () {
        var run = this.PROCESS.integration_run;
        var number_arr = [];
        var state = "complete";
        var return_value = '';
        var processGr = new GlideRecord('sn_vul_integration_process');
        processGr.addQuery('integration_run', run + "");
        processGr.addQuery("state", "IN", "waitComplete,complete");
        processGr.query();
        while (processGr.next()) {
            if (processGr.state == 'complete') {
                return_value = 'true';
                continue;
            } else {
                return_value = 'false';
                break;
            }
        }
        return return_value;
    },

    // Get all the OWASP Top 10 compliances as a concatenated string with comma.
    _getOWASPTop10: function (compliances) {
        var owasp = '';
        if (compliances != null) {
            for (var value in compliances) {
                var compliance = compliances[value].toString();
                var tempStr = compliance.toLowerCase();
                var containsStr = tempStr.indexOf('owasp top 10');
                if (containsStr != -1) {
                    if (owasp == '')
                        owasp += compliance;
                    else
                        owasp += ',' + compliance;
                }
            }
        }
        return owasp;
    },

    // Get all the SANS Top 25 compliances as a concatenated string with comma.
    _getSANSTop25: function (compliances) {
        var sans = '';
        if (compliances != null) {
            for (var value in compliances) {
                var compliance = compliances[value].toString();
                var tempStr = compliance.toLowerCase();
                var containsStr = tempStr.indexOf('sans top 25');
                if (containsStr != -1) {
                    if (sans == '')
                        sans += compliance;
                    else
                        sans += ',' + compliance;
                }
            }
        }
        return sans;
    },

    // Gets the integration parameters for vulnerability processing
    _getParameters: function(parameters) {
        var params = {
            run: null,
            remaining: {}
        };
        try {
            // Handle continuation of multi-part job
            if (parameters) {
                params = JSON.parse(parameters);
                if (params.latest) {
                    var latest = new GlideDateTime();
                    latest.setValue(params.latest);
                    params.latest = latest;
                    this.LATEST = latest;
                }
                return params;
            }

            //Updating delta start time value in Integration Instance
            var parameterName = 'delta_start_time';
            var newValue = new GlideDateTime(this.DELTA_START_TIME || '1970-01-01T10:16:06.17544Z');
            var gr = new GlideRecord("x_chec3_chexone_checkmarxone_configuration");
            gr.get('a981cec29721a510026f72021153afa6');
            var instance = gr.getValue("integration_instance");
            var implConfig = new GlideRecord("sn_sec_int_impl_config");
            implConfig.addQuery("implementation", instance);
            implConfig.query();
            while (implConfig.next()) {
                var configName = implConfig.getDisplayValue("configuration");
                if (configName == parameterName) {
                    implConfig.setValue("value", newValue);
                    implConfig.update();
                }
            }

            // Initialize delta load timestamp
            this.LATEST = new GlideDateTime(this.DELTA_START_TIME || '1970-01-01 00:00:00');
            var config = this.UTIL._getConfig(this.IMPLEMENTATION);

            // Use the new functions to get filtered projects and scans
            var projects = this._getFilteredProjects(config, this.LATEST);
            var scans = this._getFilteredScans(projects, config, this.LATEST);

            // Handle Auto-Close for Deleted Projects (if enabled)
            if (config.close_findings_of_deleted_projects) {
                var scan_app_list = [];
                var scanJson = this.UTIL.getAllScanList(this.IMPLEMENTATION, this._getCurrentDeltaStartTime());
                for (var k in scanJson.scans) {
                    if (scan_app_list.indexOf(scanJson.scans[k].projectId) == -1)
                        scan_app_list.push(scanJson.scans[k].projectId);
                }
                var deltaStartGdt = new GlideDateTime(this.DELTA_START_TIME || '1970-01-01T10:16:06.17544Z');
                var deletedProjectIds = this._getDeletedProjects(scan_app_list, deltaStartGdt);
                if (deletedProjectIds.length > 0) {
                    this._handleAppReleaseForDeletedProjects(deletedProjectIds);
                    this._handleScanSummaryForDeletedProjects(deletedProjectIds);
                    this._closeSkippedAVIsForDeletedProjects(deletedProjectIds);
                }
            }

            // Build params.remaining from filtered scans
            for (var scanId in scans) {
                var scan = scans[scanId];
                var project = projects[scan.project_sys_id];

                if (!project) continue;

                // Build scan object from filtered data
                var scanObject = {
                    scanId: scanId,
                    last_scan_date: scan.last_scan_date,
                    appname: project.app_name || '',
                    scanbranch: scan.scan_branch || '',
                    appId: project.source_app_id || '',
                    applicationIds: project.application_ids || '',
                    primaryBranch: project.primary_branch || ''
                };

                // Build parameter string from scan object
                var parameterString = this._buildScanParameterString(scanObject);
                if (!parameterString) continue;

                // Get offsets
                var offsetArray = this._getoffsets(scanObject.appId, scanObject.scanId);
                if (!offsetArray || offsetArray.length === 0) continue;

                // Add string parameter to remaining (not JSON)
                params.remaining[parameterString] = offsetArray;
            }

            // Prepare first processing item and save state
            params = this._nextParameters(params);
            if (params.run) {
                this.PROCESS.setValue('parameters', JSON.stringify(this._serializeParameters(params)));
                this.PROCESS.update();
            }

        } catch (err) {
            gs.error(this.MSG + " _getParameters: " + err);
            throw err;
        }

        return params;
    },

	// Build parameter string from scan object (converts object to semicolon-separated string)
    _buildScanParameterString: function(scanObject) {
        if (!scanObject || !scanObject.scanId) {
            return null;
        }

        // Build semicolon-separated parameter string (without engines)
        var parameterString =
            'scanId=' + (scanObject.scanId || '') +
            '; last_scan_date=' + (scanObject.last_scan_date || '') +
            '; appname=' + (scanObject.appname || '') +
            '; scanbranch=' + (scanObject.scanbranch || '') +
            '; appId=' + (scanObject.appId || '') +
            '; applicationIds=' + (scanObject.applicationIds || '') +
            '; primaryBranch=' + (scanObject.primaryBranch || '');

        return parameterString;
    },

	// Retrieves filtered projects based on delta start time and user-configured filters (ID or name/regex)
	_getFilteredProjects: function(config, deltaStartTime) {
		var projectsMap = {};
		var projectGr = new GlideRecord('sn_vul_app_release');
		
		// Build query conditions as array for better structure
		var queryConditions = [];
		queryConditions.push('source=Checkmarx One');
		queryConditions.push('active=true');
		queryConditions.push('sys_updated_on>=' + deltaStartTime.getDisplayValueInternal());
		
		var filterType = config.filter_project;
		
		// Apply project filtering based on configuration type
		if (filterType == 'by_Id') {
			var projectIdsRaw = (config.list_of_project_id_s || '').split(';');
			var isExcludeMode = projectIdsRaw.indexOf('exclude') > -1;
			var projectIds = projectIdsRaw.filter(function(id) {
				return id && id !== 'exclude';
			});

			if (projectIds.length > 0) {
				var operator = isExcludeMode ? 'NOT IN' : 'IN';
				queryConditions.push('source_app_id' + operator + projectIds.join(','));
			}
		} else if (filterType == 'by_name') {
			var projectNamesRaw = (config.project_filter_by_name || '').split(';');
			var isExcludeModeNames = projectNamesRaw.indexOf('exclude') > -1;
			var projectNames = projectNamesRaw.filter(function(name) {
				return name && name !== 'exclude';
			});

			if (projectNames.length > 0) {
				var regexPattern = projectNames.join('|');
				var operator = isExcludeModeNames ? 'NOT MATCH_REGEX' : 'MATCH_REGEX';
				queryConditions.push('app_name' + operator + regexPattern);
			}
		}

		// Join all conditions with '^' to create final encoded query
		projectGr.addEncodedQuery(queryConditions.join('^'));
		projectGr.query();

		while (projectGr.next()) {
			var projectSysId = projectGr.getUniqueValue();
			var projectData = {};

			projectData.source_app_id = projectGr.getValue('source_app_id');
			projectData.app_name = projectGr.getValue('app_name');
			projectData.primary_branch = projectGr.getValue('source_app_guid');
			projectData.source_assigned_teams = projectGr.getValue('source_assigned_teams');

			// Parse project creation date from description field (format: "...created at<ISO_DATE>")
			try {
				var description = projectGr.getValue('description') || '';
				var dateString = description.split('created at')[1];
				if (dateString) {
					// Remove microseconds if present and clean the date string
					var cleanDateString = dateString.trim().replace(/\.\d{6}Z$/, 'Z');
					var parsedDate = new GlideDateTime();
					parsedDate.setValue(cleanDateString);
					projectData.project_created_at = parsedDate.getDisplayValue();
				} else {
					projectData.project_created_at = '';
				}
			} catch (e) {
				gs.warn(this.MSG + " _getFilteredProjects: Could not parse project_created_at from description for project: " + projectSysId);
				projectData.project_created_at = '';
			}

			// Parse Application IDs from source_additional_info JSON (note: key has trailing space)
			try {
				var additionalInfoStr = projectGr.getValue('source_additional_info');
				if (additionalInfoStr) {
					var additionalInfo = JSON.parse(additionalInfoStr);
					// Key "Application Id " has intentional trailing space from original integration
					projectData.application_ids = additionalInfo["Application Id "] || '';
				} else {
					projectData.application_ids = '';
				}
			} catch (e) {
				gs.warn(this.MSG + " _getFilteredProjects: Could not parse application_ids from source_additional_info for project: " + projectSysId);
				projectData.application_ids = '';
			}

			projectsMap[projectSysId] = projectData;
		}
		return projectsMap;
	},

	// Retrieves filtered scan summaries based on project scope, delta time, and synchronization rules
	_getFilteredScans: function(projectsMap, config, deltaStartTime) {
		var scansMap = {};
		var projectSysIds = Object.keys(projectsMap);
		
		// Early return if no projects are in scope
		if (projectSysIds.length === 0) {
			return scansMap;
		}
		
		// Build query conditions as array for better structure
		var queryConditions = [];
		queryConditions.push('application_releaseIN' + projectSysIds.join(','));
		queryConditions.push('last_scan_date>=' + deltaStartTime.getDisplayValueInternal());
		queryConditions.push('active=true');
		
		// Build engine filter based on configuration
		var enginePolicyFilters = [];
		if (config.import_sast) enginePolicyFilters.push('policyCONTAINSsast');
		if (config.import_sca) enginePolicyFilters.push('policyCONTAINSsca');
		if (config.import_kics) enginePolicyFilters.push('policyCONTAINSkics');
		if (config.include_container_security) enginePolicyFilters.push('policyCONTAINScontainers');
		if (config.include_api_security) enginePolicyFilters.push('policyCONTAINSapisec');
		if (config.include_ossf_scorecard) enginePolicyFilters.push('policyCONTAINSScoreCard');
		if (config.include_secret_detection) enginePolicyFilters.push('policyCONTAINSSecretDetection');
		
		if (enginePolicyFilters.length > 0) {
			queryConditions.push('^' + enginePolicyFilters.join('^OR'));
		} else {
			gs.warn(this.MSG + " _getFilteredScans: No scan engines are enabled in the configuration.");
			return scansMap;
		}
		
		// Apply scan type filter if configured
		if (config.scan_type) {
			queryConditions.push('scan_submitted_byLIKE' + config.scan_type);
		}
		
		// Join all conditions with '^' to create final encoded query
		var scanSummaryGr = new GlideRecord('sn_vul_app_vul_scan_summary');
		scanSummaryGr.addEncodedQuery(queryConditions.join('^'));
		scanSummaryGr.orderByDesc('last_scan_date');
		scanSummaryGr.query();
		
		while (scanSummaryGr.next()) {
			var rawScanId = scanSummaryGr.getValue('source_sdlc_status');
			var projectSysId = scanSummaryGr.getValue('application_release');
			
			// Skip if scan ID is missing or project not in scope
			if (!rawScanId || !projectsMap[projectSysId]) {
				continue;
			}
			
			// Create parent scan object if first time seeing this rawScanId
			if (!scansMap[rawScanId]) {
				var scanData = {};
				
				scanData.last_scan_date = scanSummaryGr.getDisplayValue('last_scan_date');
				scanData.policy = scanSummaryGr.getValue('policy');
				scanData.project_sys_id = projectSysId;
				scanData.scan_summaries = [];
				
				// Parse branch name from tags field (format: "Branch: main | ...")
				try {
					var tags = scanSummaryGr.getValue('tags') || '';
					var branchMatch = /Branch:\s*([^|]*)/.exec(tags);
					scanData.scan_branch = branchMatch && branchMatch[1] ? branchMatch[1].trim() : '.unknown';
				} catch (e) {
					gs.warn(this.MSG + " _getFilteredScans: Could not parse branch from tags for scan: " + rawScanId);
					scanData.scan_branch = '.unknown';
				}
				
				// Parse scan type from scan_submitted_by field (format: "...Scan Type: Full Scan...")
				try {
					var submittedBy = scanSummaryGr.getValue('scan_submitted_by') || '';
					var typeMatch = /Scan Type:\s*([^\n]*)/.exec(submittedBy);
					scanData.scan_type = typeMatch && typeMatch[1] ? typeMatch[1].trim() : 'Unknown';
				} catch (e) {
					gs.warn(this.MSG + " _getFilteredScans: Could not parse scan type from scan_submitted_by for scan: " + rawScanId);
					scanData.scan_type = 'Unknown';
				}
				
				// Map policy string to engine names array
				try {
					var policyString = scanData.policy || '';
					var engines = [];
					var seenEngines = {};
					var engineMap = {
						'sast': 'sast',
						'sca': 'sca',
						'kics': 'kics',
						'containers': 'containers',
						'apisec': 'apisec',
						'ScoreCard': 'sscs-scorecard',
						'SecretDetection': 'sscs-secret-detection'
					};
					
					if (policyString) {
						var policies = policyString.split(',');
						for (var i = 0; i < policies.length; i++) {
							var policy = policies[i].trim();
							var mappedEngine = engineMap[policy];
							if (mappedEngine && !seenEngines[mappedEngine]) {
								engines.push(mappedEngine);
								seenEngines[mappedEngine] = true;
							}
						}
					}
					scanData.engines = engines;
				} catch (e) {
					gs.warn(this.MSG + " _getFilteredScans: Could not parse engines from policy for scan: " + rawScanId);
					scanData.engines = [];
				}
				
				scansMap[rawScanId] = scanData;
			}
			
			// Add engine-level summary record to scan
			var summaryData = {
				sys_id: scanSummaryGr.getUniqueValue(),
				source_scan_id: scanSummaryGr.getValue('source_scan_id')
			};
			scansMap[rawScanId].scan_summaries.push(summaryData);
		}
		
		// Apply synchronization rules based on configuration
		var syncType = config.scan_synchronization;
		var filteredScans = {};
		
		if (syncType == 'latest scan across all branches') {
			var latestScanPerProject = {};
			for (var scanId in scansMap) {
				var scan = scansMap[scanId];
				var projectSysId = scan.project_sys_id;
				var scanDate = scan.last_scan_date;
				
				if (!latestScanPerProject[projectSysId] || scanDate > latestScanPerProject[projectSysId].date) {
					latestScanPerProject[projectSysId] = {
						date: scanDate,
						scanId: scanId
					};
				}
			}
			for (var projId in latestScanPerProject) {
				var winningScanId = latestScanPerProject[projId].scanId;
				filteredScans[winningScanId] = scansMap[winningScanId];
			}
			
		} else if (syncType == 'latest scan of primary branch') {
			var latestScanPerPrimaryBranch = {};
			for (var scanId in scansMap) {
				var scan = scansMap[scanId];
				var project = projectsMap[scan.project_sys_id];
				
				if (project && project.primary_branch && scan.scan_branch === project.primary_branch) {
					var projectSysId = scan.project_sys_id;
					var scanDate = scan.last_scan_date;
					
					if (!latestScanPerPrimaryBranch[projectSysId] || scanDate > latestScanPerPrimaryBranch[projectSysId].date) {
						latestScanPerPrimaryBranch[projectSysId] = {
							date: scanDate,
							scanId: scanId
						};
					}
				}
			}
			for (var projId in latestScanPerPrimaryBranch) {
				var winningScanId = latestScanPerPrimaryBranch[projId].scanId;
				filteredScans[winningScanId] = scansMap[winningScanId];
			}
			
		} else if (syncType == 'latest scan from each branch') {
			var latestScanPerBranch = {};
			for (var scanId in scansMap) {
				var scan = scansMap[scanId];
				var branchKey = scan.project_sys_id + '_' + scan.scan_branch;
				var scanDate = scan.last_scan_date;
				
				if (!latestScanPerBranch[branchKey] || scanDate > latestScanPerBranch[branchKey].date) {
					latestScanPerBranch[branchKey] = {
						date: scanDate,
						scanId: scanId
					};
				}
			}
			for (var key in latestScanPerBranch) {
				var winningScanId = latestScanPerBranch[key].scanId;
				filteredScans[winningScanId] = scansMap[winningScanId];
			}
			
		}
		return filteredScans;
	},

    // Gets the start time of the integration
    _getCurrentDeltaStartTime: function () {
        try {
            var delta = this.UTIL.parseTZDate(this.DELTA_START_TIME) || '1970-01-01T10:16:06.17544Z';
        } catch (err) {
            gs.error(this.MSG + " _getCurrentDeltaStartTime : Error while getting the current delta start time: " + err);
            throw err;
        }
        return delta;
    },

    //to get offset (50 items at a time)
    _getoffsets: function (appId, scans) {
        var offsets = [];
        var offset = 0;
        var includeApiSecurity = this.UTIL.importApiSecurityFlaw(this.IMPLEMENTATION);
        var reportLength = this.UTIL.getTotalVulcount(this.IMPLEMENTATION, scans);
        var loopLength = reportLength / 50;
        //in result api offset value start from 0 and increment by 1, here it acts like page instead of number of item like other api
        for (var i = 0; i <= parseInt(loopLength); i++) {
            offset += 1;
            var offsetId = this._getoffset(scans, offset);
            if (offsetId) {
                offsets.push(offsetId);
                var date = new GlideDateTime();
            }
        }
        if (includeApiSecurity) {
            var pageNumber = 0;
            var apiSecLength = this.UTIL.getApiSecVulCount(this.IMPLEMENTATION, scans);
            var apiSec_loopLength = apiSecLength / 50;
            if (apiSecLength > 0) {
                for (var j = 0; j <= parseInt(apiSec_loopLength) + 1; j++) {
                    pageNumber = j * -1;
                    var finalOffset = this._getoffset(scans, pageNumber);
                    if (finalOffset && pageNumber != 0) {
                        offsets.push(finalOffset);
                    }

                }
            }
        }
        return offsets;
    },

    _getoffset: function (scanId, offsetId) {
        return offsetId;
    },

    _serializeParameters: function (params) {
        if (params.latest)
            params.latest = params.latest.getValue();
        else
            delete params.latest;
        return params;
    },

    _nextParameters: function (params) {
        params.run = null;
        var keys = Object.keys(params.remaining);
        if (keys.length) {
            params.run = {};
            var key = keys[0];
            params.run[key] = params.remaining[key][0];
            params.remaining[key] = params.remaining[key].slice(1);
            if (!params.remaining[key].length)
                delete params.remaining[key];
        }

        params.latest = this.LATEST;
        return params;
    },

    shouldRetry: function (process) {
        return true;
    },

    _getObjValues: function (obj) {
        var values = Object.keys(obj).map(function (e) {
            return obj[e];
        });
        return values;
    },

    //Get deleted projects by comparing project IDs with
    _getDeletedProjects: function (recentScanProjectIds, deltaStartGdt) {
        var deletedProjectIds = [];
        var descriptionPrefix = "created at";

        var avit = new sn_vul.PagedGlideRecord('sn_vul_app_release');
        avit.addEncodedQuery('source=Checkmarx One' + '^source_app_idNOT IN' + GlideStringUtil.escapeQueryTermSeparator(recentScanProjectIds.join(',')));
        avit.setSortField("sys_id");

        while (avit.next()) {
            var sourceAppId = avit.gr.getValue('source_app_id');
            var description = avit.gr.getValue('description');

            try {
                var dateStr = description.substring(descriptionPrefix.length).trim();
                var createdAt = new GlideDateTime();
                createdAt.setValue(this.UTIL.parseDate(dateStr));

                // Use GlideDateTime comparison: deltaStartGdt <= createdAt
                if (createdAt.onOrAfter(deltaStartGdt) && deletedProjectIds.indexOf(sourceAppId) === -1) {
                    deletedProjectIds.push(sourceAppId);
                }
            } catch (err) {
                gs.error(this.MSG + " _getDeletedProjects: Error processing/checking deletion status for project ID: " + sourceAppId + " : " + err);
            }
        }
        return deletedProjectIds;
    },

    // Updates the active field to false in discovered applications
    _handleAppReleaseForDeletedProjects: function(projectIdsToSkip) {
        var updatedCount = 0;
        var avit = new sn_vul.PagedGlideRecord('sn_vul_app_release');
        avit.addEncodedQuery('source=Checkmarx One^active=true' + '^source_app_idIN' + GlideStringUtil.escapeQueryTermSeparator(projectIdsToSkip.join(',')));
        avit.setSortField("sys_id");

        while (avit.next()) {
            avit.gr.update('active', 'false');
            updatedCount++;
        }
    },

    // Updates the active field to false in scan summary
    _handleScanSummaryForDeletedProjects: function(projectIdsToSkip) {
        var updatedCount = 0;
        var avit = new sn_vul.PagedGlideRecord('sn_vul_app_vul_scan_summary');
        avit.addEncodedQuery('source=Checkmarx One^active=true' + '^application_release.source_app_idIN' + GlideStringUtil.escapeQueryTermSeparator(projectIdsToSkip.join(',')));
        avit.setSortField("sys_id");

        while (avit.next()) {
            avit.gr.update('active', 'false');
            updatedCount++;
        }
    },

    // Close-Skipped AVIs for deleted projects
    _closeSkippedAVIsForDeletedProjects: function (projectIdsToSkip) {
        var updatedCount = 0;
        var avit = new sn_vul.PagedGlideRecord('sn_vul_app_vulnerable_item');
        avit.addEncodedQuery('source=Checkmarx One' +
            '^application_release.source_app_idIN' + GlideStringUtil.escapeQueryTermSeparator(projectIdsToSkip.join(',')) +
            '^state!=3');
        avit.setSortField("sys_id");

        while (avit.next()) {
            avit.gr.setValue('source_remediation_status', 'SKIPPED');
            avit.gr.setValue('state', 3);
            avit.gr.update('substate', 7);
            updatedCount++;
        }
    },

    type: 'CheckmarxOneAppVulItemIntegration'
});