var CheckmarxOneAppVulItemIntegration = Class.create();
CheckmarxOneAppVulItemIntegration.prototype = Object.extendsObject(sn_vul.ApplicationVulnerabilityIntegrationBase, {

    UTIL: new x_chec3_chexone.CheckmarxOneUtil(),
    MSG: "CheckmarxOneAppVulItemIntegration",

    retrieveData: function() {
        var response = "<null/>";
        var apiSecResponse = "<null/>";
        try {
            var params = this._getParameters(this.PROCESS.getValue('parameters'));

            if (params.run != null) {
                var integration_run = this.PROCESS.integration_run;


                var appname = '';
                var lastscandate = '';
                var branch = '';
                var appId = '';
                var applicationIds = [];
                var primaryBranch = '';
                var applicationIdsStr = '';
                var engines = [];
                var engine = '';
                var scanDetailedRootNodeEnd = "</scanResults>";

                var responseLastScanSummary = this.UTIL.getScanDetails(this.IMPLEMENTATION, Object.keys(params.run)[0]);
                var jsonLastScanSummResp = JSON.parse(responseLastScanSummary.getBody());
                //to map value of last_scan_date, project name and project Id in XML
                for (var value in jsonLastScanSummResp.scans) {
                    var projectResponse = this.UTIL.getProjectById(this.IMPLEMENTATION, jsonLastScanSummResp.scans[value].projectId);
                    if (null != projectResponse.applicationIds && projectResponse.applicationIds.length > 0)
                        applicationIds = applicationIds.concat(projectResponse.applicationIds);

                    if (null != projectResponse.mainBranch && '' != projectResponse.mainBranch)
                        primaryBranch = projectResponse.mainBranch.toString();

                    lastscandate += this.UTIL.parseDate(jsonLastScanSummResp.scans[value].updatedAt);
                    appname += jsonLastScanSummResp.scans[value].projectName;
                    branch += jsonLastScanSummResp.scans[value].branch;
                    appId += jsonLastScanSummResp.scans[value].projectId;
                    engines = jsonLastScanSummResp.scans[value].engines;

                    if (engines.indexOf('microengines') != -1) {
                        for (var item in jsonLastScanSummResp.scans[value].metadata.configs) {
                           if (jsonLastScanSummResp.scans[value].metadata.configs[item].type == 'microengines') {
                                var secretDetetction = jsonLastScanSummResp.scans[value].metadata.configs[item].value;
                                if ('2ms' in secretDetetction) {
                                    engines.push('SecretDetection');
                                }
                                if ('Scorecard' in secretDetetction) {
                                    engines.push('Scorecard');
                                }
                            }
                        }
                    }
                    if (engines.indexOf('containers') != -1) {
                        engines.push('CS');
                    }
                    if (engines.indexOf('kics') != -1) {
                        engines.push('IaC');
                    }
                    engine = engines.toString();
                }

                var date = new GlideDateTime(this.UTIL.parseDate(jsonLastScanSummResp.scans[value].updatedAt));
                if (!this.LATEST || date > this.LATEST)
                    this.LATEST = date;
                var isPrvScanEmpty = 'true';
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
                var scan_synchronization = config.scan_synchronization.toString();
                var scanSummary = new GlideRecord('sn_vul_app_vul_scan_summary');
                scanSummary.addQuery('application_release.source_app_id', appId);
                scanSummary.query();
                var lastSastDate;
                var lastScaDate;
                var prvScanBranch = '';
                var lastDate;
                while (scanSummary.hasNext()) {
                    scanSummary.next();
                    var tags = scanSummary.getValue('tags');
                    if (null != tags && '' != tags && 'undefined' != tags) {
                        isPrvScanEmpty = 'false';
                        var tagArr = tags.split('|', -1);
                        if (tagArr.length > 1) {
                            var record1 = tagArr[0].toString().trim();
                            var record2 = tagArr[1].toString().trim();
                            var record3 = tagArr[2].toString().trim();
                            var prvScanSummaryBranch = '';
                            var prvScanId = '';
                            var isBranchMatched = 'false';
                            var lastScanSummaryDate = scanSummary.getValue('sys_updated_on');
                            // if (record1.length > 8)
                            //     prvScanSummaryBranch = record1.substring(8);
                            if (record2.length > 12)
                                prvScanId = record2.substring(12);
                            if (record3.length > 12 && record3.substring(12) != undefined && record3.substring(12) != 'undefined' && record3.substring(12) != null)
                                prvScanSummaryBranch = record3.substring(12);
                            if (scan_synchronization == 'latest scan from each branch' && branch == prvScanSummaryBranch) {
                                isBranchMatched = 'true';
                            } else if ((scan_synchronization == 'latest scan of primary branch' || scan_synchronization == 'latest scan across all branches') && null != prvScanSummaryBranch && '' != prvScanSummaryBranch && 'undefined' != prvScanSummaryBranch) {
                                isBranchMatched = 'true';
                            }
                            if (isBranchMatched == 'true') {
                                if ((null == lastDate || '' == lastDate || 'undefined' == lastDate) || (lastDate && lastScanSummaryDate >= lastDate)) {
                                    prvScanBranch = prvScanSummaryBranch;
                                    lastDate = lastScanSummaryDate;
                                }
                            }

                        }
                    }
                }

                if (applicationIds.length > 0) {
                    applicationIdsStr = applicationIds.toString();
                }
                var offset = params.run[Object.keys(params.run)[0]];

            }
            var xml_response = '';
            if (params.run) {
                //   scanId, offset
                var scanId = Object.keys(params.run)[0];
                if (offset > 0) {
                    response = this.getDetailedReport(scanId, params.run[Object.keys(params.run)[0]], lastscandate, appname, branch, prvScanBranch, appId, applicationIdsStr, engine, severity, resultStateFilter, result_state_array);
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

                    apiSecResponse = this.getApiSecReport(scanId, params.run[Object.keys(params.run)[0]], lastscandate, appname, branch, prvScanBranch, appId, applicationIdsStr, engine);

                    if (apiSecResponse == "<null/>") {
                        xml_response = '<scanResults><Results></Results><ApiSecResults></ApiSecResults></scanResults>';
                    } else {
                        xml_response = apiSecResponse + scanDetailedRootNodeEnd;
                    }
                }

            }

        } catch (err) {
            gs.error(this.MSG + " retrieveData : Error occured while getting report. Skipping buildId: " + Object.keys(params.run)[0] + " with error: " + err);
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

    getDetailedReport: function(scanId, offset, lastscandate, appname, branch, prvScanBranch, appId, applicationIdsStr, engine, severity, resultStateFilter, result_state_array) {
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
            var basicContent = '<scanResults app_id="' + appId + '"  scan_id="' + scanId + '" last_scan_date="' + lastscandate + '" branch="' + branch + '"  engine="' + engine + '" ><Results>';
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
                if (((resultStateFilter == true && (result_state_array.indexOf(jsonLastScanReportResp.results[item].state) != -1)) ||
                        resultStateFilter == false)) {
                    if (includesast == true && jsonLastScanReportResp.results[item].type == "sast") {
                        var isSastScanIncluded = 'false';
                        var scanTypeToCheck = '';
                        if (null == configScanType || '' == configScanType)
                            isSastScanIncluded = 'true';
                        else if (null != configScanType && '' != configScanType) {
                            scanTypeToCheck = this._getScanType(this.IMPLEMENTATION, appId, scanId);
                            if (configScanType.indexOf(scanTypeToCheck) != -1)
                                isSastScanIncluded = 'true';
                        }
                        if (isSastScanIncluded == 'true') {
                            var sastseverity = jsonLastScanReportResp.results[item].severity;
                            var sast_path = '';
                            var m = 0;
                            for (j in jsonLastScanReportResp.results[item].data.nodes) {
                                if (m < 100) {
                                    var full_path = ' path:' + jsonLastScanReportResp.results[item].data.nodes[j].fileName + ' line: ' + jsonLastScanReportResp.results[item].data.nodes[j].line + ' column: ' + jsonLastScanReportResp.results[item].data.nodes[j].column;
                                    sast_path += full_path;
                                }
                            }
                            var sastScanUrl = '';

                            if (!jsonLastScanReportResp.results[item].data.resultHash.indexOf('/') == -1) {
                                sastScanUrl = apibaseurl + '/results/' + scanId + '/' + appId + '/sast?result-id=' + encodeURIComponent(jsonLastScanReportResp.results[item].data.resultHash) + '&amp;redirect=true';
                            } else {
                                sastScanUrl = apibaseurl + '/results/' + scanId + '/' + appId + '/sast';
                            }
                            var sastId = jsonLastScanReportResp.results[item].id;
                            SASTscanDetailedAll += '<result id="' + jsonLastScanReportResp.results[item].similarityId + '" scan_type="' + scan_type +
                                '" sast_id="' + sastId +
                                '" cweId="' + jsonLastScanReportResp.results[item].vulnerabilityDetails.cweId +
                                '" cweName="' + jsonLastScanReportResp.results[item].data.queryName +
                                '" category_name="' + jsonLastScanReportResp.results[item].data.queryName +
                                '" source_severity="' + jsonLastScanReportResp.results[item].severity +
                                '" package_unique_id="' + package_unique_id +
                                '" package_name="' + package_name +
                                '" location="' + jsonLastScanReportResp.results[item].data.nodes[0].fileName +
                                '" line_no="' + jsonLastScanReportResp.results[item].data.nodes[0].line +
                                '" cvssScore="' + cvssScore +
                                '" recommendation="' + recommendedVersion +
                                '" sourcefile="' + apibaseurl + '/results/' + scanId + '/' + appId + '/sast' +
                                '" cvssVector="' + cvssVector +
                                '" first_found_date="' + this.UTIL.parseDate(jsonLastScanReportResp.results[item].firstFoundAt) +
                                '" state="' + jsonLastScanReportResp.results[item].state +
                                '" status="' + jsonLastScanReportResp.results[item].status +
                                '" app_id="' + appId +
                                '" branch="' + branch +
                                '" prvBranch="' + prvScanBranch +
                                '" last_scan_date="' + lastscandate +
                                '" application_ids="' + applicationIdsStr +
                                '" scan_id="' + 'sast' + scanId + '">' +
                                '<references><' + '![CDATA[' + sast_path + ']]' + '></references>' +
                                '<resultHash><' + '![CDATA[' + jsonLastScanReportResp.results[item].data.resultHash + ']]' + '></resultHash>' +
                                '<description><' + '![CDATA[' + jsonLastScanReportResp.results[item].description + ']]' + '></description></result>';
                        }
                    }

                    if (includesca == true && jsonLastScanReportResp.results[item].type == "sca") {
                        var exploitable_method = '';
                        for (var k in jsonLastScanReportResp.results[item].data.packageData) {
                            var url = jsonLastScanReportResp.results[item].data.packageData[k].url;
                            ref += url + ',  ';
                            var sca_packageID = jsonLastScanReportResp.results[item].data.packageIdentifier;
                            recommendedVersion = jsonLastScanReportResp.results[item].data.recommendedVersion;
                        }

                        if (jsonLastScanReportResp.results[item].data.exploitableMethods != null) {

                            for (var exp in jsonLastScanReportResp.results[item].data.exploitableMethods) {
                                var exp_path = 'fullName= ' + jsonLastScanReportResp.results[item].data.exploitableMethods[exp].fullName +
                                    ' || SourceFile= ' + jsonLastScanReportResp.results[item].data.exploitableMethods[exp].sourceFile + ';  ';
                            }

                            exploitable_method = 'Exploitable methods: ' + exp_path;
                        }
                        var scaseverity = jsonLastScanReportResp.results[item].severity;
                        SCAscanDetailedAll += '<result id="' + jsonLastScanReportResp.results[item].id +
                            '" scan_type="' + 'sca' +
                            '" cweId="' + jsonLastScanReportResp.results[item].vulnerabilityDetails.cweId +
                            '" cweName="' + jsonLastScanReportResp.results[item].vulnerabilityDetails.cveName +
                            '" cvssScore="' + jsonLastScanReportResp.results[item].vulnerabilityDetails.cvssScore +
                            '" cvssVector="' + jsonLastScanReportResp.results[item].vulnerabilityDetails.cvss.attackVector +
                            '" category_name="' + jsonLastScanReportResp.results[item].vulnerabilityDetails.cweId +
                            '" source_severity="' + jsonLastScanReportResp.results[item].severity +
                            '" first_found_date="' + this.UTIL.parseDate(jsonLastScanReportResp.results[item].firstFoundAt) +
                            '" state="' + jsonLastScanReportResp.results[item].state +
                            '" status="' + jsonLastScanReportResp.results[item].status +
                            '" package_unique_id="' + sca_packageID +
                            '" recommendation="' + recommendedVersion +
                            '" package_name="' + sca_packageID +
                            '" sourcefile="' + apibaseurl + '/results/' + appId + '/' + scanId + '/sca' +
                            '" line_no="' + line +
                            '" location="' + location +
                            '" app_id="' + appId +
                            '" branch="' + branch +
                            '" prvBranch="' + prvScanBranch +
                            '" exploitable_method="' + exploitable_method +
                            '" last_scan_date="' + lastscandate +
                            '" application_ids="' + applicationIdsStr +
                            '" scan_id="' + 'sca' + scanId + '">' +
                            '<references><' + '![CDATA[' + ref + ']]' + '></references>' +
                            '<description><' + '![CDATA[' + jsonLastScanReportResp.results[item].description + ']]' + '></description></result>';
                    }
                    if (includekics == true && jsonLastScanReportResp.results[item].type == "kics") {
                        var kicsseverity = jsonLastScanReportResp.results[item].severity;

                        var kicsowasp = this._getOWASPTop10(jsonLastScanReportResp.results[item].vulnerabilityDetails.compliances);
                        var kicssans = this._getSANSTop25(jsonLastScanReportResp.results[item].vulnerabilityDetails.compliances);
                        KICSscanDetailedAll += '<result id="' + jsonLastScanReportResp.results[item].similarityId + '" scan_type="' + 'kics' +
                            '" cweId="' + jsonLastScanReportResp.results[item].data.queryId +
                            '" cweName="' + jsonLastScanReportResp.results[item].data.queryName +
                            '" category_name="' + jsonLastScanReportResp.results[item].data.queryName +
                            '" source_severity="' + jsonLastScanReportResp.results[item].severity +
                            '" package_unique_id="' + package_unique_id +
                            '" package_name="' + package_name +
                            '" location="' + jsonLastScanReportResp.results[item].data.fileName +
                            '" line_no="' + jsonLastScanReportResp.results[item].data.line +
                            '" cvssScore="' + cvssScore +
                            '" recommendation="' + recommendedVersion +
                            '" sourcefile="' + apibaseurl + '/results/' + scanId + '/' + appId + '/kics' +
                            '" cvssVector="' + cvssVector +
                            '" first_found_date="' + this.UTIL.parseDate(jsonLastScanReportResp.results[item].firstFoundAt) +
                            '" state="' + jsonLastScanReportResp.results[item].state +
                            '" status="' + jsonLastScanReportResp.results[item].status +
                            '" app_id="' + appId +
                            '" branch="' + branch +
                            '" prvBranch="' + prvScanBranch +
                            '" last_scan_date="' + lastscandate +
                            '" OWASPTop10="' + kicsowasp +
                            '" SANSTop25="' + kicssans +
                            '" application_ids="' + applicationIdsStr +
                            '" scan_id="' + 'IaC' + scanId + '">' +
                            '<references><' + '![CDATA[' + notes + ']]' + '></references>' +
                            '<description><' + '![CDATA[' + jsonLastScanReportResp.results[item].description + ']]' + '></description></result>';
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
                        conSecScanDetailedAll += '<result id="' + jsonLastScanReportResp.results[item].similarityId + '" scan_type="' + 'containers' +
                            '" cweId="' + jsonLastScanReportResp.results[item].vulnerabilityDetails.cweId +
                            '" cweName="' + jsonLastScanReportResp.results[item].vulnerabilityDetails.cveName +
                            '" category_name="' + jsonLastScanReportResp.results[item].vulnerabilityDetails.cweId +
                            '" source_severity="' + jsonLastScanReportResp.results[item].severity +
                            '" package_unique_id="' + package_unique_id +
                            '" package_name="' + packageName +
                            '" location="' + jsonLastScanReportResp.results[item].data.imageFilePath +
                            '" line_no="' + line +
                            '" cvssScore="' + jsonLastScanReportResp.results[item].vulnerabilityDetails.cvssScore +
                            '" recommendation="' + recommendedVersion +
                            '" sourcefile="' + apibaseurl + '/container-security-results/' + appId + '/' + scanId + '/results/' +
                            '" cvssVector="' + access_vector +
                            '" first_found_date="' + this.UTIL.parseDate(jsonLastScanReportResp.results[item].firstFoundAt) +
                            '" state="' + jsonLastScanReportResp.results[item].state +
                            '" status="' + jsonLastScanReportResp.results[item].status +
                            '" app_id="' + appId +
                            '" branch="' + branch +
                            '" prvBranch="' + prvScanBranch +
                            '" last_scan_date="' + lastscandate +
                            '" application_ids="' + applicationIdsStr +
                            '" result_hash="' + result_hash +
                            '" scan_id="' + 'CS' + scanId + '">' +
                            '<references><' + '![CDATA[' + notes + ']]' + '></references>' +
                            '<description><' + '![CDATA[' + jsonLastScanReportResp.results[item].description + ']]' + '></description></result>';
                    }
                    // secret detection
                    if (includeSecretDetection == true && jsonLastScanReportResp.results[item].type == "sscs-secret-detection") {
                        var secretDetectionSeverity = jsonLastScanReportResp.results[item].severity;
                        secretDetectionScanDetailedAll += '<result id="' + jsonLastScanReportResp.results[item].similarityId + '_' + jsonLastScanReportResp.results[item].id +
                            '" scan_type="' + 'SecretDetection' +
                            '" cweId="' + jsonLastScanReportResp.results[item].id +
                            '" cweName="' + '' +
                            '" category_name="' + jsonLastScanReportResp.results[item].data.ruleName +
                            '" source_severity="' + jsonLastScanReportResp.results[item].severity +
                            '" package_unique_id="' + package_unique_id +
                            '" package_name="' + package_name +
                            '" location="' + jsonLastScanReportResp.results[item].data.fileName +
                            '" line_no="' + jsonLastScanReportResp.results[item].data.line +
                            '" cvssScore="' + cvssScore +
                            '" recommendation="' + recommendedVersion +
                            '" sourcefile="' + apibaseurl + '/results/' + scanId + '/' + appId + '/kics' +
                            '" cvssVector="' + cvssVector +
                            '" first_found_date="' + this.UTIL.parseDate(jsonLastScanReportResp.results[item].firstFoundAt) +
                            '" state="' + jsonLastScanReportResp.results[item].state +
                            '" status="' + jsonLastScanReportResp.results[item].status +
                            '" app_id="' + appId +
                            '" branch="' + branch +
                            '" prvBranch="' + prvScanBranch +
                            '" last_scan_date="' + lastscandate +
                            '" application_ids="' + applicationIdsStr +
                            '" scan_id="' + 'SecretDetection' + scanId + '">' +
                            '<source_notes><' + '![CDATA[' + jsonLastScanReportResp.results[item].data.ruleDescription + ']]' + '></source_notes>' +
                            '<remediation><' + '![CDATA[' + 'Remediation: ' + jsonLastScanReportResp.results[item].data.remediation + ', Remediation link:' +
                            jsonLastScanReportResp.results[item].data.remediationLink +
                            ', Remediation Additional= ' + jsonLastScanReportResp.results[item].data.remediationAdditional + ']]' + '></remediation>' +
                            '<description><' + '![CDATA[' + jsonLastScanReportResp.results[item].description + ']]' + '></description></result>';
                    }


                    // scorecard detection
                    if (includeScoreCard == true && jsonLastScanReportResp.results[item].type == "sscs-scorecard") {
                        var scorecardSeverity = jsonLastScanReportResp.results[item].severity;
                        scorecardScanDetailedAll += '<result id="' + jsonLastScanReportResp.results[item].similarityId + '_' + jsonLastScanReportResp.results[item].id +
                            '" scan_type="' + 'ScoreCard' +
                            '" cweId="' + jsonLastScanReportResp.results[item].id +
                            '" cweName="' + '' +
                            '" category_name="' + jsonLastScanReportResp.results[item].data.ruleName +
                            '" source_severity="' + jsonLastScanReportResp.results[item].severity +
                            '" package_unique_id="' + package_unique_id +
                            '" package_name="' + package_name +
                            '" location="' + jsonLastScanReportResp.results[item].data.fileName +
                            '" line_no="' + jsonLastScanReportResp.results[item].data.line +
                            '" cvssScore="' + cvssScore +
                            '" recommendation="' + recommendedVersion +
                            '" sourcefile="' + apibaseurl + '/results/' + scanId + '/' + appId + '/kics' +
                            '" cvssVector="' + cvssVector +
                            '" first_found_date="' + this.UTIL.parseDate(jsonLastScanReportResp.results[item].firstFoundAt) +
                            '" state="' + jsonLastScanReportResp.results[item].state +
                            '" status="' + jsonLastScanReportResp.results[item].status +
                            '" app_id="' + appId +
                            '" branch="' + branch +
                            '" prvBranch="' + prvScanBranch +
                            '" last_scan_date="' + lastscandate +
                            '" application_ids="' + applicationIdsStr +
                            '" scan_id="' + 'ScoreCard' + scanId + '">' +
                            '<source_notes><' + '![CDATA[' + jsonLastScanReportResp.results[item].data.ruleDescription + ']]' + '></source_notes>' +
                            '<remediation><' + '![CDATA[' + 'Remediation: ' + jsonLastScanReportResp.results[item].data.remediation + ', Remediation link:' +
                            jsonLastScanReportResp.results[item].data.remediationLink +
                            ', Remediation Additional= ' + jsonLastScanReportResp.results[item].data.remediationAdditional + ']]' + '></remediation>' +
                            '<description><' + '![CDATA[' + jsonLastScanReportResp.results[item].description + ']]' + '></description></result>';
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

    getApiSecReport: function(scanId, offset, lastscandate, appname, branch, prvScanBranch, appId, applicationIdsStr, engine) {
        try {
            var newoffset = offset - offset * 2;
            var basicContent = '<scanResults app_id="' + appId + '"  scan_id="' + scanId + '" last_scan_date="' + lastscandate + '" branch="' + branch + '"><Results></Results><ApiSecResults>';
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
                    apiSecScanDetailedAll += '<apisec appId="' + appId +
                        '" scanId="' + scanId +
                        '" sast_risk_id="' + jsonApiSecScanReportResp.entries[entry].sast_risk_id +
                        '" affected_url="' + affectedUrl + '"/>';
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
    customSleep: function(ms) {
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
    _getScanType: function(configId, appId, scanId) {
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
    _getLatestProcessRecord: function() {
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
    _getOWASPTop10: function(compliances) {
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
    _getSANSTop25: function(compliances) {
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

    // Gets the integration parameters as a map
    _getParameters: function(parameters) {
        var params = {
            run: null,
            remaining: {}
        };

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
                var app_list = [];
                var scan_app_list = [];
                var project_primary_branch_list = [];
                this.LATEST = new GlideDateTime(this.DELTA_START_TIME || '1970-01-01T10:16:06.17544Z').getDate();
                var apps = this.AVR_API.getAppReleases();
                var scanJson = this.UTIL.getAllScanList(this.IMPLEMENTATION, this._getCurrentDeltaStartTime());
                var offsetId = '';
                var config = this.UTIL._getConfig(this.IMPLEMENTATION);
                var scan_synchronization = config.scan_synchronization.toString();
                var filter_project = config.filter_project;
                var list_projects = this.UTIL.getConfigProjectList(this.IMPLEMENTATION);
                var list_projects_name = this.UTIL.getConfigProjectNameList(this.IMPLEMENTATION);
                if (list_projects_name && list_projects_name.length > 0 && filter_project == 'by_name')
                    var projectIdsByNames = this.UTIL.getProjectIdsFromProjectNames(this.IMPLEMENTATION, list_projects_name);
                for (var j in apps) {
                    app_list.push(apps[j].source_app_id);
                }
                for (var k in scanJson.scans) {
                    if (scan_app_list.indexOf(scanJson.scans[k].projectId) == -1)
                        scan_app_list.push(scanJson.scans[k].projectId);
                }
                var scans = [];
                if (scan_synchronization == 'latest scan of primary branch') {
                    project_primary_branch_list = this.UTIL.getProjectPrimaryBranchList(this.IMPLEMENTATION);
                }
                for (var item in scan_app_list) {
                    var scanId = '';
                    var appId = scan_app_list[item];
                    if (appId !== "undefined" && app_list.indexOf(appId) != -1) {
                        var includeProjectFlag = this.UTIL.isProjectIncluded(this.IMPLEMENTATION, filter_project, list_projects, list_projects_name, projectIdsByNames, appId);

                        if (includeProjectFlag == 'true') {
                            if (scan_synchronization == 'latest scan of primary branch') {
                                scanId = this._getPrimaryBranchScanId(scanJson, appId, project_primary_branch_list);

                                if (scanId && scanId != '' && scanId != 'undefined') {
                                    scans.push(scanId);
                                } else {
                                    scanId = this._getScanIdFromJSON(scanJson, appId);
                                    if (scanId && scanId != '' && scanId != 'undefined')
                                        scans.push(scanId);
                                }
                            } else if (scan_synchronization == 'latest scan from each branch') {
                                var scans_list = this._getLastScanIdFromBranch(scanJson, appId);
                                scans.push.apply(scans, scans_list);


                            } else if (scan_synchronization == 'latest scan across all branches' || scans.length == 0) {
                                scanId = this._getScanIdFromJSON(scanJson, appId);
                                if (scanId && scanId != '' && scanId != 'undefined') {
                                    scans.push(scanId);
                                }
                            }
                        }
                    }
                }
                if (scans.length > 0) {
                    for (var id in scans) {
                        var scan = scans[id];
                        offsetId = this._getoffsets(appId, scan);
                        params.remaining[scan] = offsetId;

                    }
                }
                params = this._nextParameters(params);
                if (params.run) {
                    this.PROCESS.setValue('parameters', JSON.stringify(this._serializeParameters(params)));
                    this.PROCESS.update();
                }
            }
        } catch (err) {
            gs.error(this.MSG + " _getParameters : Error while getting the integration parameters: " + err);
            throw err;
        }
        return params;
    },

    //get Scan IDs from JSON
    _getScanIdFromJSON: function(scanJson, appId) {
        var scanId = '';
        var includesca = this.UTIL.importScaFlaw(this.IMPLEMENTATION);
        var includesast = this.UTIL.importSastFlaw(this.IMPLEMENTATION);
        var includekics = this.UTIL.importKicsFlaw(this.IMPLEMENTATION);
        var includeContainerSecurity = this.UTIL.importContainerSecurityFlaw(this.IMPLEMENTATION);
        var includeSecretDetection = this.UTIL.importSecretDetectionFlaw(this.IMPLEMENTATION);
        var includeScoreCard = this.UTIL.importScoreCardFlaw(this.IMPLEMENTATION);
        for (var item in scanJson.scans) {
            var projectId = scanJson.scans[item].projectId;
            var projectScanId = scanJson.scans[item].id;
            var includeScan = 'false';
            if (projectId && projectId != '' && projectId != 'undefined' && projectId == appId) {
                if (includesca) {
                    if (scanJson.scans[item].engines.toString().indexOf("sca") != -1)
                        includeScan = 'true';
                }
                if (includesast) {
                    if (scanJson.scans[item].engines.toString().indexOf("sast") != -1)
                        includeScan = 'true';
                }
                if (includekics) {
                    if (scanJson.scans[item].engines.toString().indexOf("kics") != -1)
                        includeScan = 'true';
                }
                if (includeContainerSecurity) {
                    if (scanJson.scans[item].engines.toString().indexOf("containers") != -1)
                        includeScan = 'true';
                }
                if (includeSecretDetection) {
                    if (scanJson.scans[item].engines.toString().indexOf("microengines") != -1)
                        includeScan = 'true';
                }
                if (includeScoreCard) {
                    if (scanJson.scans[item].engines.toString().indexOf("microengines") != -1)
                        includeScan = 'true';
                }
            }
            if (includeScan == 'true') {
                scanId = projectScanId;
                break;
            }
        }
        return scanId;
    },

    //get Scan ID for Primary Branch
    _getPrimaryBranchScanId: function(scanJson, appId, project_primary_branch_list) {
        var scanId = '';
        var includesca = this.UTIL.importScaFlaw(this.IMPLEMENTATION);
        var includesast = this.UTIL.importSastFlaw(this.IMPLEMENTATION);
        var includekics = this.UTIL.importKicsFlaw(this.IMPLEMENTATION);
        var includeContainerSecurity = this.UTIL.importContainerSecurityFlaw(this.IMPLEMENTATION);
        var includeSecretDetection = this.UTIL.importSecretDetectionFlaw(this.IMPLEMENTATION);
        var includeScoreCard = this.UTIL.importScoreCardFlaw(this.IMPLEMENTATION);
        var includeApiSecurity = this.UTIL.importApiSecurityFlaw(this.IMPLEMENTATION);
        var primaryBranch = this.UTIL.getPrimaryBranchByProjectId(project_primary_branch_list, appId);
        if (null != primaryBranch && '' != primaryBranch) {
            for (var item in scanJson.scans) {
                var projectId = scanJson.scans[item].projectId;
                var projectScanId = scanJson.scans[item].id;
                var branch = scanJson.scans[item].branch;
                var includeScan = 'false';
                if (projectId && projectId != '' && projectId != 'undefined' && projectId == appId && primaryBranch == branch) {
                    if (includesca) {
                        if (scanJson.scans[item].engines.toString().indexOf("sca") != -1)
                            includeScan = 'true';
                    }
                    if (includesast) {
                        if (scanJson.scans[item].engines.toString().indexOf("sast") != -1)
                            includeScan = 'true';
                    }
                    if (includekics) {
                        if (scanJson.scans[item].engines.toString().indexOf("kics") != -1)
                            includeScan = 'true';
                    }

                    if (includeContainerSecurity) {
                        if (scanJson.scans[item].engines.toString().indexOf("containers") != -1)
                            includeScan = 'true';
                    }
                    if (includeSecretDetection) {
                        if (scanJson.scans[item].engines.toString().indexOf("microengines") != -1)
                            includeScan = 'true';
                    }
                    if (includeScoreCard) {
                        if (scanJson.scans[item].engines.toString().indexOf("microengines") != -1)
                            includeScan = 'true';
                    }
                }
                if (includeScan == 'true') {
                    scanId = projectScanId;
                    break;
                }
            }
        }
        return scanId;
    },


    //get Scan ID for Each Branch
    _getLastScanIdFromBranch: function(scanJson, appId) {
        var scanId = [];
        var branch = [];
        var includesca = this.UTIL.importScaFlaw(this.IMPLEMENTATION);
        var includesast = this.UTIL.importSastFlaw(this.IMPLEMENTATION);
        var includekics = this.UTIL.importKicsFlaw(this.IMPLEMENTATION);
        var includeContainerSecurity = this.UTIL.importContainerSecurityFlaw(this.IMPLEMENTATION);
        var includeSecretDetection = this.UTIL.importSecretDetectionFlaw(this.IMPLEMENTATION);
        var includeScoreCard = this.UTIL.importScoreCardFlaw(this.IMPLEMENTATION);
        var includeApiSecurity = this.UTIL.importApiSecurityFlaw(this.IMPLEMENTATION);
        for (var item in scanJson.scans) {
            var projectId = scanJson.scans[item].projectId;
            var projectScanId = scanJson.scans[item].id;
            var scanIdBranch = scanJson.scans[item].branch;
            var includeScan = 'false';
            if (projectId && projectId != '' && projectId != 'undefined' && projectId == appId && branch.indexOf(scanIdBranch) == -1) {
                if (includesca) {
                    if (scanJson.scans[item].engines.toString().indexOf("sca") != -1)
                        includeScan = 'true';
                }
                if (includesast) {
                    if (scanJson.scans[item].engines.toString().indexOf("sast") != -1)
                        includeScan = 'true';
                }
                if (includekics) {
                    if (scanJson.scans[item].engines.toString().indexOf("kics") != -1)
                        includeScan = 'true';
                }

                if (includeContainerSecurity) {
                    if (scanJson.scans[item].engines.toString().indexOf("containers") != -1)
                        includeScan = 'true';
                }
                if (includeSecretDetection) {
                    if (scanJson.scans[item].engines.toString().indexOf("microengines") != -1)
                        includeScan = 'true';
                }
                if (includeScoreCard) {
                    if (scanJson.scans[item].engines.toString().indexOf("microengines") != -1)
                        includeScan = 'true';
                }
            }
            if (includeScan == 'true') {
                branch.push(scanJson.scans[item].branch);
                scanId.push(projectScanId);

            }
        }
        return scanId;
    },




    // Gets the start time of the integration
    _getCurrentDeltaStartTime: function() {
        try {
            var delta = this.UTIL.parseTZDate(this.DELTA_START_TIME) || '1970-01-01T10:16:06.17544Z';
        } catch (err) {
            gs.error(this.MSG + " _getCurrentDeltaStartTime : Error while getting the current delta start time: " + err);
            throw err;
        }
        return delta;
    },

    //to get offset (50 items at a time)
    _getoffsets: function(appId, scanId) {
        var offsets = [];
        var offset = 0;
        var includeApiSecurity = this.UTIL.importApiSecurityFlaw(this.IMPLEMENTATION);
        var reportLength = this.UTIL.getTotalVulcount(this.IMPLEMENTATION, scanId);
        var loopLength = reportLength / 50;
        //in result api offset value start from 0 and increment by 1, here it acts like page instead of number of item like other api
        for (var i = 0; i <= parseInt(loopLength); i++) {
            offset += 1;
            var offsetId = this._getoffset(scanId, offset);
            if (offsetId) {
                offsets.push(offsetId);
                var date = new GlideDateTime();
            }
        }
        if (includeApiSecurity) {
            var pageNumber = 0;
            var apiSecLength = this.UTIL.getApiSecVulCount(this.IMPLEMENTATION, scanId);
            var apiSec_loopLength = apiSecLength / 50;
            if (apiSecLength > 0) {
                for (var j = 0; j <= parseInt(apiSec_loopLength) + 1; j++) {
                    pageNumber = j * -1;
                    var finalOffset = this._getoffset(scanId, pageNumber);
                    if (finalOffset && pageNumber != 0) {
                        offsets.push(finalOffset);
                    }

                }
            }
        }
        return offsets;
    },

    _getoffset: function(scanId, offsetId) {
        return offsetId;
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
            params.run[key] = params.remaining[key][0];
            params.remaining[key] = params.remaining[key].slice(1);
            if (!params.remaining[key].length)
                delete params.remaining[key];
        }

        params.latest = this.LATEST;
        return params;
    },

    shouldRetry: function(process) {
        return true;
    },

    _getObjValues: function(obj) {
        var values = Object.keys(obj).map(function(e) {
            return obj[e];
        });
        return values;
    },

    type: 'CheckmarxOneAppVulItemIntegration'
});