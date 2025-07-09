var CheckmarxOneScanSummaryIntegration = Class.create();
CheckmarxOneScanSummaryIntegration.prototype = Object.extendsObject(sn_vul.ApplicationVulnerabilityIntegrationBase, {

    UTIL: new x_chec3_chexone.CheckmarxOneUtil(),
    MSG: 'CheckmarxOneScanSummaryIntegration:',

    retrieveData: function () {
        var response = "<null/>";
        try {
            var params = this._getParameters(this.PROCESS.getValue('parameters'));
            if (params.run) {
                //  appId,  offset
                var appId = Object.keys(params.run)[0];
                var offsetId = params.run[Object.keys(params.run)[0]];
                response = this.getSummaryReport(appId, offsetId);
            }

        } catch (err) {
            gs.error(this.MSG + " retrieveData : Error while retrieving the data. Skipping appId: " + appId + err);
            response = '<scanData><scaScanData><scans></scans></scaScanData><sastScanData><scans></scans></sastScanData><kicsScanData><scans></scans></kicsScanData></scanData>';
        }
        if (response == "<null/>") {
            response = '<scanData><scaScanData><scans></scans></scaScanData><sastScanData><scans></scans></sastScanData><kicsScanData><scans></scans></kicsScanData></scanData>';
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
            contents: new GlideSysAttachment().write(this.PROCESS, this.FILENAME, "xml", response),
            contentType: "sys_attachment",
            extension: "xml"
        };

    },

    //Creates XML summary for given scan Id
    getSummaryReport: function (appId, offsetId) {
        try {
            var scanSummaryRootNodeStart = "<scanData>";
            var scanSummaryRootNodeEnd = "</scanData>";
            var scaScanSummaryAll = '';
            var sastScanSummaryAll = '';
            var kicsScanSummaryAll = '';
            var containerSecurityScanSummaryAll = '';
            var apiSecurityScanSummaryAll = '';
            var scoreCardScanSummaryAll = '';
            var secretDetectionScanSummaryAll = '';
            var includescanSummaryAll = '';
            var newoffset = offsetId - 1;
            var includesca = this.UTIL.importScaFlaw(this.IMPLEMENTATION);
            var includesast = this.UTIL.importSastFlaw(this.IMPLEMENTATION);
            var includekics = this.UTIL.importKicsFlaw(this.IMPLEMENTATION);
            var includeContainerSecurity = this.UTIL.importContainerSecurityFlaw(this.IMPLEMENTATION);
            var includeApiSecurity = this.UTIL.importApiSecurityFlaw(this.IMPLEMENTATION);

            var includeSecretDetection = this.UTIL.importSecretDetectionFlaw(this.IMPLEMENTATION);
            var includeScoreCard = this.UTIL.importScoreCardFlaw(this.IMPLEMENTATION);
            var config = this.UTIL._getConfig(this.IMPLEMENTATION);
            var scan_synchronization = config.scan_synchronization.toString();
            var primaryBranch = '';
            var jsonLastScanSummResp = '';
            var branches;
            if (scan_synchronization == 'latest scan of primary branch') {
                primaryBranch = this.UTIL.getProjectById(this.IMPLEMENTATION, appId).mainBranch.toString();
                if (null != primaryBranch && '' != primaryBranch) {
                    jsonLastScanSummResp = this.UTIL.getScanListFilterByBranch(this.IMPLEMENTATION, appId, this._getCurrentDeltaStartTime(), primaryBranch);
                    branches = this.UTIL.getProjectBranchList(this.IMPLEMENTATION, appId);
                } else
                    jsonLastScanSummResp = this.UTIL.getScanInfo(this.IMPLEMENTATION, appId, newoffset, this._getCurrentDeltaStartTime());
            } else if (scan_synchronization == 'latest scan from each branch') {
                branches = this.UTIL.getProjectBranchList(this.IMPLEMENTATION, appId);
                if (null != branches && '' != branches) {
                    jsonLastScanSummResp = this.UTIL.getScanListFilterByMultipleBranch(this.IMPLEMENTATION, appId, this._getCurrentDeltaStartTime(), branches);
                }
            } else if (scan_synchronization == 'latest scan across all branches' || jsonLastScanSummResp == '' || jsonLastScanSummResp == null || jsonLastScanSummResp == -1) {
                jsonLastScanSummResp = this.UTIL.getScanInfo(this.IMPLEMENTATION, appId, newoffset, this._getCurrentDeltaStartTime());
            }
            var lastSastDate;
            var lastScaDate;
            var lastKicsDate;
            var lastConSecDate;
            var lastApiSecDate;
            var lastScoreCardDate;
            var lastSecretDetectionDate;
            var branch = [];
            var configScanType = config.scan_type.toString();
            for (var item in jsonLastScanSummResp.scans) {
                var engine = '';
                var engineList = [];
                if (jsonLastScanSummResp.scans[item].engines.toString().indexOf("microengines") != -1) {
                    var found = false;
                    var value2ms = null;
                    var valueScorecard = null;

                    // Loop through configs
                    for (var i = 0; i < jsonLastScanSummResp.scans[item].metadata.configs.length; i++) {
                        if (jsonLastScanSummResp.scans[item].metadata.configs[i].type === "microengines") {
                            found = true;
                            if (jsonLastScanSummResp.scans[item].metadata.configs[i].value) {
                                value2ms = jsonLastScanSummResp.scans[item].metadata.configs[i].value["2ms"];
                                valueScorecard = jsonLastScanSummResp.scans[item].metadata.configs[i].value["scorecard"];
                            }
                            break;
                        }
                    }
                    if (value2ms == true || value2ms == 'true') {
                        engine += 'SecretDetection,';
                    }
                    if (valueScorecard == true || valueScorecard == 'true') {
                        engine += 'Scorecard,';
                    }
                }

                if (jsonLastScanSummResp.scans[item].engines.toString().indexOf('containers') != -1 && engineList.indexOf('CS') == -1) {
                    engine += 'CS,';
                }
                if (jsonLastScanSummResp.scans[item].engines.toString().indexOf('kics') != -1 && engineList.indexOf('IaC') == -1) {
                    engine += 'IaC,';
                }
                var start = 0;

                for (var j = 0; j < engine.length; j++) {
                    if (engine[j] === ",") {
                        engineList.push(engine.slice(start, j));
                        start = j + 1;
                    }
                }
                engineList.push(engine.slice(start));
                var engines = engine + jsonLastScanSummResp.scans[item].engines;
                //sca scan summary
                if (includesca && jsonLastScanSummResp.scans[item].engines.toString().indexOf("sca") != -1 && branch.indexOf(jsonLastScanSummResp.scans[item].branch) == -1) {
                    var scaresponsevul = this.UTIL.getScanSummaryInfo(this.IMPLEMENTATION, jsonLastScanSummResp.scans[item].id);
                    var scaScanType = "Full Scan";
                    if (scaresponsevul != -1) {
                      
                        scaScanSummaryAll += '<scan id="' + this.UTIL.escapeXmlChars('sca' + jsonLastScanSummResp.scans[item].id) + '"' +
                            ' app_id="' + this.UTIL.escapeXmlChars(appId) + '"' +
                            ' last_scan_date="' + this.UTIL.escapeXmlChars(this.UTIL.parseDate(jsonLastScanSummResp.scans[item].updatedAt)) + '"' +
                            ' total_no_flaws="' + this.UTIL.escapeXmlChars(scaresponsevul) + '"' +
                            ' branch="' + this.UTIL.escapeXmlChars(jsonLastScanSummResp.scans[item].branch) + '"' +
                            ' scan_origin="' + this.UTIL.escapeXmlChars(jsonLastScanSummResp.scans[item].sourceOrigin) + '"' +
                            ' scan_source="' + this.UTIL.escapeXmlChars(jsonLastScanSummResp.scans[item].sourceType) + '"' +
                            ' scan_type="' + this.UTIL.escapeXmlChars(scaScanType) + '"' +
                            ' scan_id="' + this.UTIL.escapeXmlChars(jsonLastScanSummResp.scans[item].id) + '"' +
                            ' engine="' + this.UTIL.escapeXmlChars(engines) + '"' +
                            ' app_name="' + this.UTIL.escapeXmlChars(appId) + '"/>';
                    }
                }

                //sast scan summary
                if (includesast && jsonLastScanSummResp.scans[item].engines.toString().indexOf("sast") != -1 && branch.indexOf(jsonLastScanSummResp.scans[item].branch) == -1) {
                    var sastresponsevul = this.UTIL.getSastScanSummaryInfo(this.IMPLEMENTATION, jsonLastScanSummResp.scans[item].id);
                    var sastScanTypeToCheck = '';

                    if (configScanType.indexOf('fastScanMode') != -1) {
                        var isFastScan = this._isFastScanMode(this.IMPLEMENTATION, appId, jsonLastScanSummResp.scans[item].id);
                        if (isFastScan == 'true')
                            sastScanTypeToCheck = 'fastScanMode';
                    }
                    if (sastScanTypeToCheck == '' && configScanType != 'fastScanMode' && jsonLastScanSummResp.scans[item].metadata.configs[0].value) {
                        sastScanTypeToCheck = jsonLastScanSummResp.scans[item].metadata.configs[0].value.incremental == "false" ? "fullScan" : "incrementalScan";
                    }
                    if (jsonLastScanSummResp.scans[item].metadata.configs[0].value) {
                        var sastScanType = jsonLastScanSummResp.scans[item].metadata.configs[0].value.incremental == "false" ? "Full Scan" : "Incremental Scan";
                    }
                    if (sastresponsevul != -1 && ((null == configScanType || '' == configScanType) || (sastScanTypeToCheck != '' && configScanType.indexOf(sastScanTypeToCheck) != -1))) {
                        var loc = this._getLOCforSAST(jsonLastScanSummResp.scans[item].statusDetails);
                        sastScanSummaryAll += '<scan id="' + this.UTIL.escapeXmlChars('sast' + jsonLastScanSummResp.scans[item].id) + '"' +
                            ' app_id="' + this.UTIL.escapeXmlChars(appId) + '"' +
                            ' last_scan_date="' + this.UTIL.escapeXmlChars(this.UTIL.parseDate(jsonLastScanSummResp.scans[item].updatedAt)) + '"' +
                            ' total_no_flaws="' + this.UTIL.escapeXmlChars(sastresponsevul) + '"' +
                            ' loc="' + this.UTIL.escapeXmlChars(loc) + '"' +
                            ' branch="' + this.UTIL.escapeXmlChars(jsonLastScanSummResp.scans[item].branch) + '"' +
                            ' scan_origin="' + this.UTIL.escapeXmlChars(jsonLastScanSummResp.scans[item].sourceOrigin) + '"' +
                            ' scan_source="' + this.UTIL.escapeXmlChars(jsonLastScanSummResp.scans[item].sourceType) + '"' +
                            ' scan_type="' + this.UTIL.escapeXmlChars(sastScanType) + '"' +
                            ' scan_id="' + this.UTIL.escapeXmlChars(jsonLastScanSummResp.scans[item].id) + '"' +
                            ' engine="' + this.UTIL.escapeXmlChars(engines) + '"' +
                            ' app_name="' + this.UTIL.escapeXmlChars(appId) + '"/>';
                    }
                }

                //kics scan summary
                if (includekics && jsonLastScanSummResp.scans[item].engines.toString().indexOf("kics") != -1 && branch.indexOf(jsonLastScanSummResp.scans[item].branch) == -1) {
                    var kicsresponsevul = this.UTIL.getKicsScanSummaryInfo(this.IMPLEMENTATION, jsonLastScanSummResp.scans[item].id);
                    var scanType = "Full Scan";
                    if (kicsresponsevul != -1) {
                        kicsScanSummaryAll += '<scan id="' + this.UTIL.escapeXmlChars('IaC' + jsonLastScanSummResp.scans[item].id) + '"' +
                            ' app_id="' + this.UTIL.escapeXmlChars(appId) + '"' +
                            ' last_scan_date="' + this.UTIL.escapeXmlChars(this.UTIL.parseDate(jsonLastScanSummResp.scans[item].updatedAt)) + '"' +
                            ' total_no_flaws="' + this.UTIL.escapeXmlChars(kicsresponsevul) + '"' +
                            ' branch="' + this.UTIL.escapeXmlChars(jsonLastScanSummResp.scans[item].branch) + '"' +
                            ' scan_origin="' + this.UTIL.escapeXmlChars(jsonLastScanSummResp.scans[item].sourceOrigin) + '"' +
                            ' scan_source="' + this.UTIL.escapeXmlChars(jsonLastScanSummResp.scans[item].sourceType) + '"' +
                            ' scan_type="' + this.UTIL.escapeXmlChars(scanType) + '"' +
                            ' scan_id="' + this.UTIL.escapeXmlChars(jsonLastScanSummResp.scans[item].id) + '"' +
                            ' engine="' + this.UTIL.escapeXmlChars(engines) + '"' +
                            ' app_name="' + this.UTIL.escapeXmlChars(appId) + '"/>';
                    }
                }

                //Container Security scan summary
                if (includeContainerSecurity && jsonLastScanSummResp.scans[item].engines.toString().indexOf("containers") != -1 && branch.indexOf(jsonLastScanSummResp.scans[item].branch) == -1) {
                    var containerSecurityResponseVul = this.UTIL.getContainerSecurityScanSummaryInfo(this.IMPLEMENTATION, jsonLastScanSummResp.scans[item].id);
                    var container_scanType = "Full Scan";
                    if (containerSecurityResponseVul != -1) {
                        containerSecurityScanSummaryAll += '<scan id="' + this.UTIL.escapeXmlChars('CS' + jsonLastScanSummResp.scans[item].id) + '"' +
                            ' app_id="' + this.UTIL.escapeXmlChars(appId) + '"' +
                            ' last_scan_date="' + this.UTIL.escapeXmlChars(this.UTIL.parseDate(jsonLastScanSummResp.scans[item].updatedAt)) + '"' +
                            ' total_no_flaws="' + this.UTIL.escapeXmlChars(containerSecurityResponseVul) + '"' +
                            ' branch="' + this.UTIL.escapeXmlChars(jsonLastScanSummResp.scans[item].branch) + '"' +
                            ' scan_origin="' + this.UTIL.escapeXmlChars(jsonLastScanSummResp.scans[item].sourceOrigin) + '"' +
                            ' scan_source="' + this.UTIL.escapeXmlChars(jsonLastScanSummResp.scans[item].sourceType) + '"' +
                            ' scan_type="' + this.UTIL.escapeXmlChars(container_scanType) + '"' +
                            ' scan_id="' + this.UTIL.escapeXmlChars(jsonLastScanSummResp.scans[item].id) + '"' +
                            ' engine="' + this.UTIL.escapeXmlChars(engines) + '"' +
                            ' app_name="' + this.UTIL.escapeXmlChars(appId) + '"/>';
                    }
                }

                // API Security scan summary
                if (includeApiSecurity && jsonLastScanSummResp.scans[item].engines.toString().indexOf("apisec") != -1 && branch.indexOf(jsonLastScanSummResp.scans[item].branch) == -1) {
                    var apiSecResponseVul = this.UTIL.getApiSecurityScanSummaryInfo(this.IMPLEMENTATION, jsonLastScanSummResp.scans[item].id);
                    var api_scanType = "Full Scan";
                    if (apiSecResponseVul != -1) {
                        apiSecurityScanSummaryAll += '<scan id="' + this.UTIL.escapeXmlChars('apisec' + jsonLastScanSummResp.scans[item].id) + '"' +
                            ' app_id="' + this.UTIL.escapeXmlChars(appId) + '"' +
                            ' last_scan_date="' + this.UTIL.escapeXmlChars(this.UTIL.parseDate(jsonLastScanSummResp.scans[item].updatedAt)) + '"' +
                            ' total_no_flaws="' + this.UTIL.escapeXmlChars(apiSecResponseVul) + '"' +
                            ' branch="' + this.UTIL.escapeXmlChars(jsonLastScanSummResp.scans[item].branch) + '"' +
                            ' scan_origin="' + this.UTIL.escapeXmlChars(jsonLastScanSummResp.scans[item].sourceOrigin) + '"' +
                            ' scan_source="' + this.UTIL.escapeXmlChars(jsonLastScanSummResp.scans[item].sourceType) + '"' +
                            ' scan_type="' + this.UTIL.escapeXmlChars(api_scanType) + '"' +
                            ' scan_id="' + this.UTIL.escapeXmlChars(jsonLastScanSummResp.scans[item].id) + '"' +
                            ' engine="' + this.UTIL.escapeXmlChars(engines) + '"' +
                            ' app_name="' + this.UTIL.escapeXmlChars(appId) + '"/>';
                    }
                }
                //OSSF Scorecard scan summary
                if (includeScoreCard && jsonLastScanSummResp.scans[item].engines.toString().indexOf("microengines") != -1 && branch.indexOf(jsonLastScanSummResp.scans[item].branch) == -1) {
                    var scorecardResponseVul = this.UTIL.getScoreCardScanSummaryInfo(this.IMPLEMENTATION, jsonLastScanSummResp.scans[item].id);
                    var scorecard_scanType = "Full Scan";
                    if (scorecardResponseVul != -1) {
                        scoreCardScanSummaryAll += '<scan id="' + this.UTIL.escapeXmlChars('ScoreCard' + jsonLastScanSummResp.scans[item].id) + '"' +
                            ' app_id="' + this.UTIL.escapeXmlChars(appId) + '"' +
                            ' last_scan_date="' + this.UTIL.escapeXmlChars(this.UTIL.parseDate(jsonLastScanSummResp.scans[item].updatedAt)) + '"' +
                            ' total_no_flaws="' + this.UTIL.escapeXmlChars(scorecardResponseVul) + '"' +
                            ' branch="' + this.UTIL.escapeXmlChars(jsonLastScanSummResp.scans[item].branch) + '"' +
                            ' scan_origin="' + this.UTIL.escapeXmlChars(jsonLastScanSummResp.scans[item].sourceOrigin) + '"' +
                            ' scan_source="' + this.UTIL.escapeXmlChars(jsonLastScanSummResp.scans[item].sourceType) + '"' +
                            ' scan_type="' + this.UTIL.escapeXmlChars(scorecard_scanType) + '"' +
                            ' scan_id="' + this.UTIL.escapeXmlChars(jsonLastScanSummResp.scans[item].id) + '"' +
                            ' engine="' + this.UTIL.escapeXmlChars(engines) + '"' +
                            ' app_name="' + this.UTIL.escapeXmlChars(appId) + '"/>';
                    }
                }

                //secretDetection scan summary
                if (includeSecretDetection && jsonLastScanSummResp.scans[item].engines.toString().indexOf("microengines") != -1 && branch.indexOf(jsonLastScanSummResp.scans[item].branch) == -1) {
                    var secretDetectionResponseVul = this.UTIL.getSecretDetectionScanSummaryInfo(this.IMPLEMENTATION, jsonLastScanSummResp.scans[item].id);
                    var secretDetection_scanType = "Full Scan";
                    if (secretDetectionResponseVul != -1) {
                        secretDetectionScanSummaryAll += '<scan id="' + this.UTIL.escapeXmlChars('SecretDetection' + jsonLastScanSummResp.scans[item].id) + '"' +
                            ' app_id="' + this.UTIL.escapeXmlChars(appId) + '"' +
                            ' last_scan_date="' + this.UTIL.escapeXmlChars(this.UTIL.parseDate(jsonLastScanSummResp.scans[item].updatedAt)) + '"' +
                            ' total_no_flaws="' + this.UTIL.escapeXmlChars(secretDetectionResponseVul) + '"' +
                            ' branch="' + this.UTIL.escapeXmlChars(jsonLastScanSummResp.scans[item].branch) + '"' +
                            ' scan_origin="' + this.UTIL.escapeXmlChars(jsonLastScanSummResp.scans[item].sourceOrigin) + '"' +
                            ' scan_source="' + this.UTIL.escapeXmlChars(jsonLastScanSummResp.scans[item].sourceType) + '"' +
                            ' scan_type="' + this.UTIL.escapeXmlChars(secretDetection_scanType) + '"' +
                            ' scan_id="' + this.UTIL.escapeXmlChars(jsonLastScanSummResp.scans[item].id) + '"' +
                            ' engine="' + this.UTIL.escapeXmlChars(engines) + '"' +
                            ' app_name="' + this.UTIL.escapeXmlChars(appId) + '"/>';
                    }
                }


                branch.push(jsonLastScanSummResp.scans[item].branch);

                var date = new GlideDateTime(this.UTIL.parseDate(jsonLastScanSummResp.scans[item].updatedAt));
                if (!this.LATEST || date > this.LATEST)
                    this.LATEST = date;
            }
            if (includesca) {
                includescanSummaryAll += "<scaScanData><scans>" + scaScanSummaryAll + "</scans></scaScanData>";
            }
            if (includesast) {
                includescanSummaryAll += "<sastScanData><scans>" + sastScanSummaryAll + "</scans></sastScanData>";
            }
            if (includekics) {
                includescanSummaryAll += "<kicsScanData><scans>" + kicsScanSummaryAll + "</scans></kicsScanData>";
            }
            if (includeContainerSecurity) {
                includescanSummaryAll += "<conSecScanData><scans>" + containerSecurityScanSummaryAll + "</scans></conSecScanData>";
            }
            if (includeApiSecurity) {
                includescanSummaryAll += "<apiSecScanData><scans>" + apiSecurityScanSummaryAll + "</scans></apiSecScanData>";
            }
            if (includeScoreCard) {
                includescanSummaryAll += "<scoreCardScanData><scans>" + scoreCardScanSummaryAll + "</scans></scoreCardScanData>";
            }
            if (includeSecretDetection) {
                includescanSummaryAll += "<secretDetectionScanData><scans>" + secretDetectionScanSummaryAll + "</scans></secretDetectionScanData>";
            }

            reportContent = scanSummaryRootNodeStart + includescanSummaryAll + scanSummaryRootNodeEnd;
        } catch (err) {
            gs.error(this.MSG + " getSummaryReport : Error while getting the scan summary report: " + err);
            throw err;
        }
        return reportContent;
    },

    //get Fast Scan Mode value
    _isFastScanMode: function (configId, appId, scanId) {
        var scanResponse = this.UTIL.getScanConfigInfo(configId, appId, scanId);
        var isFastScan = 'false';
        try {
            for (var item in scanResponse) {

                var key = scanResponse[item].key.toString();

                if (key == 'scan.config.sast.fastScanMode') {
                    var value = scanResponse[item].value.toString();
                    if (value == 'true')
                        isFastScan = 'true';
                    break;
                }
            }
        } catch (err) {
            gs.error(this.MSG + "_isFastScanMode: Error occured while getting fast scan mode: " + err);
            throw err;
        }
        return isFastScan;
    },


    // Gets the integration parameters as a map
    _getParameters: function (parameters) {
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
                    gs.debug(this.MSG + 'latest time' + latest);
                }
            } else {
                this.LATEST = new GlideDateTime(this.DELTA_START_TIME || '1970-01-01T10:16:06.17544Z').getDate();
                var apps = this.AVR_API.getAppReleases();
                projectIdsByLastScanDate = this.UTIL.getprojectScanList(this.IMPLEMENTATION, this._getCurrentDeltaStartTime());

                var config = this.UTIL._getConfig(this.IMPLEMENTATION);
                var filter_project = config.filter_project;
                var list_projects = this.UTIL.getConfigProjectList(this.IMPLEMENTATION);
                var list_projects_name = this.UTIL.getConfigProjectNameList(this.IMPLEMENTATION);
                if (list_projects_name && list_projects_name.length > 0 && filter_project == 'by_name')
                    var projectIdsByNames = this.UTIL.getProjectIdsFromProjectNames(this.IMPLEMENTATION, list_projects_name);

                for (var j in apps) {
                    app_list.push(apps[j].source_app_id);
                }

                for (var item in projectIdsByLastScanDate) {
                    var appId = projectIdsByLastScanDate[item];
                    if (appId !== "undefined" && app_list.indexOf(appId) != -1) {
                        var includeProjectFlag = this.UTIL.isProjectIncluded(this.IMPLEMENTATION, filter_project, list_projects, list_projects_name, projectIdsByNames, appId);
                        if (includeProjectFlag == 'true') {
                            offsetId = this._getoffsets(appId);
                            params.remaining[appId] = offsetId;
                        }
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
            // throw err;
        }
        return params;
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

    //to get offset(to get offset value as 1 , to get details of last scan)
    _getoffsets: function (appId) {
        var offsets = [];
        var offset = 1;
        var loopLength = 1;
        var offsetId = this._getoffset(appId, offset);
        if (offsetId) {
            offsets.push(offsetId);
            var date = new GlideDateTime();
        }
        return offsets;
    },

    _getoffset: function (appId, offsetId) {
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

    //Presently returning the same buildId. 
    _getScan: function (appId, buildId) {
        return buildId;
    },

    shouldRetry: function (process) {
        return true;
    },

    _getLOCforSAST: function (statusDetails) {
        var loc = -1;

        if (null != statusDetails && statusDetails.length > 0) {
            for (var index in statusDetails) {
                var statusDetail = statusDetails[index];
                if (null != statusDetail && null != statusDetail.name && 'sast' == statusDetail.name && null != statusDetail.loc) {
                    loc = statusDetail.loc;
                    break;
                }
            }
        }

        return loc;
    },

    type: 'CheckmarxOneScanSummaryIntegration'
});