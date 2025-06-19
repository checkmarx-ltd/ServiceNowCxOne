var CheckmarxOneAppVulItemProcessor = Class.create();
CheckmarxOneAppVulItemProcessor.prototype = Object.extendsObject(sn_vul.ApplicationVulnerabilityImportProcessorBase, {

    MSG: 'CheckmarxOne Application Vulnerable Item Processor: ',
    NOT_AVAILABLE: 'Not Available',
    UTIL: new x_chec3_chexone.CheckmarxOneUtil(),

    import_static_flaws: null,

    process: function(attachment) {

        if (attachment) {
            try {
                this.UTIL.validateXML(new GlideSysAttachment().getContent(attachment), 'error');
                var doc = new XMLDocument2();
                doc.parseXML(new GlideSysAttachment().getContent(attachment));
                var result_node = doc.getNode('/scanResults');
                var result_iter = result_node.getChildNodeIterator();
                while (result_iter.hasNext()) {
                    if (result_iter.next().getNodeName().includes("Results")) {
                        var listNode = doc.getNode('/scanResults/Results');
                    }
                    if (result_iter.next().getNodeName().includes("ApiSecResults")) {
                        var apiSecResultsNode = doc.getNode('/scanResults/ApiSecResults');
                        // Process API Security results
                        if (apiSecResultsNode) {
                            var apiSecIter = apiSecResultsNode.getChildNodeIterator();
                            while (apiSecIter.hasNext()) {
                                try {
                                    var apiSecNode = apiSecIter.next();
                                    this._handleApiSecurity(
                                        apiSecNode.getAttribute('appId'),
                                        apiSecNode.getAttribute('scanId'),
                                        apiSecNode.getAttribute('sast_risk_id'),
                                        apiSecNode.getAttribute('affected_url'));
                                } catch (ex) {
                                    gs.error(this.MSG + "Error processing API Security entry: " + ex);
                                }
                            }
                        }
                    }
                }

            } catch (ex) {
                gs.info("error reported" + new GlideSysAttachment().getContent(attachment));
                gs.error(this.MSG + "Error occurred while validating or parsing the XML: " + ex);
                throw ex;
            }
            var reportData = {};
            var errorProcess = '';
            var avitArr = [];
            var engineArr = [];
            var config = this.UTIL._getConfig('1234');
            var includesca = this.UTIL.importScaFlaw('1234');
            var includesast = this.UTIL.importSastFlaw('1234');
            var includekics = this.UTIL.importKicsFlaw('1234');
            var includeContainerSecurity = this.UTIL.importContainerSecurityFlaw('1234');
            var includeSecretDetection = this.UTIL.importSecretDetectionFlaw('1234');
            var includeScoreCard = this.UTIL.importScoreCardFlaw('1234');
            if (includesast) {
                engineArr.push('sast');
            }
            if (includesca) {
                engineArr.push('sca');
            }
            if (includekics) {
                engineArr.push('IaC');
            }
            if (includeContainerSecurity) {
                engineArr.push('CS');
            }
            if (includeSecretDetection) {
                engineArr.push('SecretDetection');
            }
            if (includeScoreCard) {
                engineArr.push('ScoreCard');
            }
            var scan_synchronization = config.scan_synchronization.toString();
            var include_only_similarity_id = config.include_only_similarity_id;
            var basicData = {};
            basicData['source_app_id'] = result_node.getAttribute('app_id');
            basicData['app_name'] = result_node.getAttribute('app_id');
            basicData['app_version'] = this.NOT_AVAILABLE;
            basicData['source_scan_id'] = result_node.getAttribute('scan_id');
            basicData['last_scan_date'] = new GlideDateTime(result_node.getAttribute('last_scan_date'));
            basicData['scan_summary_name'] = basicData['source_scan_id'] + ' ' + basicData['last_scan_date'];
            basicData['branch'] = result_node.getAttribute('branch');
            basicData['engines'] = result_node.getAttribute('engine');
            var project_branch = basicData.branch;
            if (listNode) {
                var iter = listNode.getChildNodeIterator();
                while (iter.hasNext()) {
                    try {
                        var node = iter.next();
                        reportData['source_app_id'] = node.getAttribute('app_id');
                        reportData['source_scan_id'] = node.getAttribute('scan_id');
                        reportData['last_scan_date'] = new GlideDateTime(node.getAttribute('last_scan_date'));
                        reportData['scan_summary_name'] = reportData['source_scan_id'] + ' ' + reportData['last_scan_date'];
                        if (node.getAttribute('scan_type') == 'kics' || node.getAttribute('scan_type') == 'SecretDetection' ||
                            node.getAttribute('scan_type') == 'ScoreCard') {
                            reportData['scan_type'] = 'static';
                        } else if (node.getAttribute('scan_type') == 'containers') {
                            reportData['scan_type'] = 'sca';
                        } else {
                            reportData['scan_type'] = node.getAttribute('scan_type');
                        }
                        reportData['application_Id'] = node.getAttribute('application_ids').toString();
                        var queryData = {};
                        var nvdData = {};
                        var resultObj = {};
                        var projectId = node.getAttribute('app_id');
                        var scan_type = node.getAttribute('scan_type');

                        var source_severity_string = node.getAttribute('source_severity');
                        if (source_severity_string == 'CRITICAL') {
                            var source_severity = 0;
                        } else if (source_severity_string == 'HIGH') {
                            source_severity = 1;
                        } else if (source_severity_string == 'MEDIUM') {
                            source_severity = 2;
                        } else if (source_severity_string == 'LOW') {
                            source_severity = 3;
                        } else if (source_severity_string == 'INFO') {
                            source_severity = 4;
                        } else {
                            source_severity = 5;
                        }

                        queryData['category_name'] = node.getAttribute('category_name');
                        var query_id = 'Checkmarx One' + "-" + node.getAttribute('id');
                        var cwe_name = node.getAttribute('cweName');
                        queryData['scan_type'] = reportData['scan_type'];
                        queryData['source_severity'] = +source_severity;
                        queryData['threat'] = '';
                        reportData['cweId'] = node.getAttribute('cweId');
                        queryData['cvss_base_score'] = node.getAttribute('cvssScore');
                        queryData['cvss_vector'] = node.getAttribute('cvssVector');
                        queryData['last_detection_date'] = reportData.last_scan_date.getDate();
                        if (reportData['scan_type'] == 'static') {
                            if (node.getAttribute('OWASPTop10') != '') {
                                var owaspObj = {};
                                owaspObj[gs.getMessage("OWASPTop10")] = node.getAttribute('OWASPTop10');
                                queryData['owasp'] = JSON.stringify(owaspObj);
                            }
                            queryData['short_description'] = node.getAttribute('SANSTop25');
                        }

                        // to check if first_detection_date checkbox is selected
                        var include_first_detection_date = this.UTIL.getFirstDetectionDate();
                        if (include_first_detection_date) {
                            queryData['first_detection_date'] = new GlideDateTime(node.getAttribute('first_found_date')).getDate();
                            resultObj['first_found'] = new GlideDateTime(node.getAttribute('first_found_date')).getDate();
                        }

                        reportData['cweName'] = node.getAttribute('cweName');
                        if (node.getAttribute('recommendation') != '') {
                            resultObj['source_recommendation'] = 'Recommended version-' + node.getAttribute('recommendation');
                        }
                        var branch = node.getAttribute('branch');
                        var prvBranch = node.getAttribute('prvBranch');
                        var similarityIdToUpsert = '';
                        if (scan_type == 'static') {
                            var resultHash = '';
                            var childIter = node.getChildNodeIterator();
                            while (childIter.hasNext) {
                                var childNode = childIter.next();
                                if (childNode.getNodeName() == "resultHash") {
                                    resultHash = childNode.getTextContent();
                                    break;
                                }
                            }

                            queryData['source_entry_id'] = 'Checkmarx One' + " CWE-" + reportData['cweId'];
                            queryData['cwe_list'] = [{
                                cwe_id: reportData['cweId'],
                                name: queryData['category_name']
                            }];
                            var similarityId = node.getAttribute('id');
                            var digest = new GlideDigest();
                            var similarityIdHash = similarityId + '_' + resultHash;
                            resultObj['source_request'] = similarityId;
                            if (include_only_similarity_id) {
                                similarityIdToUpsert = similarityId;
                            } else {
                                this._handleSimilarityId(similarityId, similarityIdHash, projectId);
                                similarityIdToUpsert = similarityIdHash;
                            }
                            resultObj['source_notes'] = node.getFirstChild().getTextContent().toString();
                            resultObj['source_exploit'] = node.getAttribute('sast_id');
                        }

                        if (scan_type == 'sca') {
                            queryData['source_entry_id'] = 'Checkmarx One' + "-" + node.getAttribute('id');
                            var scaAvitId = node.getAttribute('id') + node.getAttribute('package_unique_id');
                            similarityIdToUpsert = scaAvitId;
                            resultObj['source_references'] = node.getFirstChild().getTextContent().toString();
                            resultObj['source_notes'] = node.getAttribute('exploitable_method').toString();

                        }
                        if (scan_type == 'kics') {
                            queryData['source_entry_id'] = 'Checkmarx One' + "-" + node.getAttribute('cweId');
                            var kicsavitId = node.getAttribute('id');
                            similarityIdToUpsert = kicsavitId;
                            resultObj['source_notes'] = node.getFirstChild().getTextContent().toString();
                        }

                        if (scan_type == 'containers') {
                            queryData['source_entry_id'] = 'Checkmarx One' + "-" + node.getAttribute('cweId');
                            var consecAvitId = node.getAttribute('id') + '_' + node.getAttribute('result_hash');
                            similarityIdToUpsert = consecAvitId;
                        }
                        if (scan_type == 'SecretDetection' || scan_type == 'ScoreCard') {
                            queryData['source_entry_id'] = 'Checkmarx One' + "-" + node.getAttribute('cweId');
                            var secretDetectionAvitId = node.getAttribute('id');
                            similarityIdToUpsert = secretDetectionAvitId;
                            var remediation = '';
                            var remediationIter = node.getChildNodeIterator();
                            while (remediationIter.hasNext) {
                                var remediationNode = remediationIter.next();
                                if (remediationNode.getNodeName() == "remediation") {
                                    remediation = remediationNode.getTextContent();
                                    break;
                                }
                            }
                            resultObj['source_recommendation'] = remediation;
                            resultObj['source_notes'] = node.getFirstChild().getTextContent().toString();
                        }

                        if (branch == null || branch == '' || branch == '.unknown' || branch == 'undefined')
                            resultObj['source_avit_id'] = similarityIdToUpsert;
                        else {
                            this._handleSimilarityIdHashForBranches(similarityIdToUpsert, projectId, prvBranch, branch, scan_synchronization);
                            if (scan_synchronization == 'latest scan from each branch') {
                                resultObj['source_avit_id'] = similarityIdToUpsert + branch;
                            } else if (scan_synchronization == 'latest scan across all branches' || scan_synchronization == 'latest scan of primary branch') {
                                resultObj['source_avit_id'] = similarityIdToUpsert;
                            }
                        }
                        resultObj['source_app_id'] = reportData['source_app_id'];
                        resultObj['scan_type'] = reportData['scan_type'];
                        resultObj['package_unique_id'] = node.getAttribute('package_unique_id');
                        resultObj['package_name'] = node.getAttribute('package_name');
                        resultObj['location'] = node.getAttribute('location');
                        resultObj['source_sdlc_status'] = 'Not Applicable';
                        resultObj['source_link'] = node.getAttribute('sourcefile');
                        if (node.getAttribute('line_no') && node.getAttribute('line_no') != '' && node.getAttribute('line_no') != null && parseInt(node.getAttribute('line_no'), 10) > -1) {
                            resultObj['line_number'] = parseInt(node.getAttribute('line_no'), 10);
                        }
                        resultObj['source_scan_id'] = reportData['source_scan_id'];
                        resultObj['last_scan_date'] = reportData['last_scan_date'];
                        resultObj['scan_summary_name'] = reportData['scan_summary_name'];
                        resultObj['description'] = node.getLastChild().getTextContent().toString();

                        resultObj['source_vulnerability_explanation'] = node.getLastChild().getTextContent().toString();
                        if (reportData['scan_type'] == 'static') {
                            var status = this.UTIL.getSASTRemediationStatus(node.getAttribute('status'), node.getAttribute('state'));
                        } else {
                            status = this.UTIL.getSCARemediationStatus(node.getAttribute('status'), node.getAttribute('state'));
                        }

                        resultObj['source_remediation_status'] = status;
                        var infObj = {};
                        infObj[gs.getMessage("Application Id")] = node.getAttribute('application_ids').toString();
                        infObj[gs.getMessage("Branch Name")] = node.getAttribute('branch');
                        infObj[gs.getMessage("Project Id")] = node.getAttribute('app_id');
                        resultObj['source_additional_info'] = JSON.stringify(infObj);
                        resultObj['source_finding_status'] = node.getAttribute('state');
                        resultObj['last_found'] = reportData.last_scan_date.getDate();
                        resultObj['source_severity'] = source_severity_string;
                        resultObj['complies_with_policy'] = 'not_applicable';
                        resultObj['source_entry_id'] = queryData['source_entry_id'];
                        resultObj['category_name'] = queryData['category_name'];
                        resultObj['project_branch'] = node.getAttribute('branch');
                        if (reportData['scan_type'] != 'static') {
                            nvdData['cvss_base_score'] = node.getAttribute('cvssScore');
                            nvdData['cvss_vector'] = node.getAttribute('cvssVector');
                            this._handleCVE(nvdData, resultObj, cwe_name);
                        }
                        this._upsertQuery(queryData);
                        this._upsertAVIT(resultObj);
                        var scan_intials = '';
                        if (reportData.source_scan_id.slice(0, 2) == 'CS') {
                            scan_intials = 'CS';
                        } else {
                            scan_intials = reportData.source_scan_id.slice(0, 3);
                        }
                        // this._handleFixedAVITwithScanIntials(basicData.source_scan_id, reportData.source_app_id, project_branch, scan_synchronization, scan_intials);

                    } catch (ex) {
                        errorMessage = gs.getMessage("Error in retriving data for app vulnerability item integration!");
                        gs.error(this.MSG + " " + errorMessage + " " + ex.message);
                        errorProcess += " | " + ex.message;

                    }

                }
            }
            if (basicData.engines != '') {
                this._handleFixedAVIT(basicData.source_scan_id, basicData.source_app_id, project_branch, scan_synchronization, basicData.engines, engineArr);
            }
            if (!gs.nil(errorProcess))
                gs.error(this.MSG + "All errors that occurred while processing Vulnerability lists: " + errorProcess);
            this.completeProcess(this.integrationProcessGr, this.import_counts);
        } else
            gs.warn(this.MSG + ':process called with no attachment');

    },

    //updating data to app vul entry table
    _upsertQuery: function(data) {
        try {
            var result = this.AVR_API.createOrUpdateAppVulEntry(data);
            if (!result)
                return;
            if (result.updated)
                this.import_counts.updated++;
            else if (result.inserted)
                this.import_counts.inserted++;
            else if (result.unchanged)
                this.import_counts.unchanged++;
        } catch (err) {
            gs.error(this.MSG + " _upsert : Error while inserting data into ServiceNow App Vul Entry Table." + err);

        }
    },
    //updating data to app vul item table
    _upsertAVIT: function(data) {
        try {
            var result = this.AVR_API.createOrUpdateAVIT(data);
            if (!result)
                return;
            if (result.updated) {
                this.import_counts.updated++;
            } else if (result.inserted) {
                this.import_counts.inserted++;
            } else if (result.unchanged) {
                this.import_counts.unchanged++;
            }

        } catch (err) {
            gs.error(this.MSG + " _upsert : Error while inserting data into ServiceNow App Vul Item Table." + err);
        }
    },

    _handleSimilarityId: function(similarityId, similarityIdHash, projectId) {
        var avit = new sn_vul.PagedGlideRecord('sn_vul_app_vulnerable_item');
        avit.addQuery('source_avit_id', similarityId);
        avit.setSortField("sys_id");
        while (avit.next()) {
            var appId = avit.gr.application_release.source_app_id;
            if (appId == projectId) {
                avit.gr.setValue('source_avit_id', similarityIdHash);
                avit.gr.setValue('source_request', similarityId);
                avit.gr.update();
            }
        }
    },

    _getAvitDetailsByProjectId: function(projectId) {
        var avitArr = [];
        var avit = new GlideRecord('sn_vul_app_vulnerable_item');
        avit.addQuery('application_release.source_app_id', projectId);
        avit.query();
        while (avit.next()) {
            if (null != avit && null != avit.source_avit_id && '' != avit.source_avit_id)
                avitArr.push(avit.getValue('source_avit_id'));
        }
        return avitArr;
    },

    _handleSimilarityIdHashForBranches: function(similarityIdHash, projectId, oldScanBranch, scanBranch, scan_synchronization) {
        var similarityIdToCheck = '';
        var similarityIdToUpdate = '';

        if (scan_synchronization == 'latest scan from each branch') {
            similarityIdToCheck = similarityIdHash;
            similarityIdToUpdate = similarityIdHash + scanBranch;
        } else if ((scan_synchronization == 'latest scan across all branches' || scan_synchronization == 'latest scan of primary branch') && null != oldScanBranch && '' != oldScanBranch && 'undefined' != oldScanBranch && '.unknown' != oldScanBranch) {
            similarityIdToCheck = similarityIdHash + oldScanBranch;
            similarityIdToUpdate = similarityIdHash;
        }

        if (similarityIdToCheck != '' && similarityIdToUpdate != '') {
            var avit = new sn_vul.PagedGlideRecord('sn_vul_app_vulnerable_item');
            avit.addQuery('source_avit_id', similarityIdToCheck);
            avit.setSortField("sys_id");
            while (avit.next()) {
                var appId = avit.gr.application_release.source_app_id;
                if (appId == projectId) {
                    avit.gr.setValue('source_avit_id', similarityIdToUpdate);
                    avit.gr.setValue('project_branch', scanBranch);
                    avit.gr.update();
                }
            }
        }
    },

    _handleFixedAVIT: function(source_scan_id, projectId, branch, scan_synchronization, engines, engineArr) {
        var start = 0;
        var engineList = [];
        for (var i = 0; i < engines.length; i++) {
            if (engines[i] === ",") {
                engineList.push(engines.slice(start, i));
                start = i + 1;
            }
        }
        engineList.push(engines.slice(start));
        for (var item in engineList) {
            if (engineArr.indexOf(engineList[item]) != -1) {
                var avit = new sn_vul.PagedGlideRecord('sn_vul_app_vulnerable_item');
                if (scan_synchronization == 'latest scan from each branch' && (branch != null || branch != '' || branch != '.unknown' || branch != 'undefined')) {
                    avit.addEncodedQuery('application_release.source_app_id=' + GlideStringUtil.escapeQueryTermSeparator(projectId) + '^app_vul_scan_summaryNOT LIKE' + GlideStringUtil.escapeQueryTermSeparator(source_scan_id) +
                        '^state!=3^project_branch=' + GlideStringUtil.escapeQueryTermSeparator(branch) + '^app_vul_scan_summarySTARTSWITH' +
                        GlideStringUtil.escapeQueryTermSeparator(engineList[item]));
                } else {
                    avit.addEncodedQuery('application_release.source_app_id=' + GlideStringUtil.escapeQueryTermSeparator(projectId) + '^app_vul_scan_summaryNOT LIKE' + GlideStringUtil.escapeQueryTermSeparator(source_scan_id) + '^state!=3' + '^app_vul_scan_summarySTARTSWITH' + GlideStringUtil.escapeQueryTermSeparator(engineList[item]));
                }
                avit.setSortField("sys_id");
                while (avit.next()) {
                    avit.gr.setValue('source_remediation_status', 'FIXED');
                    avit.gr.setValue('state', 3);
                    avit.gr.update('substate', 4);
                }
            }
        }
    },

    // To map API security vul info to exisiting sast vul items
    _handleApiSecurity: function(source_app_id, source_scan_id, sast_risk_id, affected_url) {
        var avit = new sn_vul.PagedGlideRecord('sn_vul_app_vulnerable_item');
        avit.addEncodedQuery('application_release.source_app_id=' + GlideStringUtil.escapeQueryTermSeparator(source_app_id) + '^app_vul_scan_summaryLIKE' + GlideStringUtil.escapeQueryTermSeparator(source_scan_id) + '^source_exploit=' + GlideStringUtil.escapeQueryTermSeparator(sast_risk_id));
        //avit.addQuery('source_exploit', sast_risk_id);
        avit.setSortField("sys_id");
        while (avit.next()) {
            avit.gr.setValue('affected_url', affected_url);
            avit.gr.update();
        }
    },

    _handleCVE: function(nvdData, resultObj, cve) {
        var name = cve;
        var url = resultObj.source_references;
        var cvss_base_score = nvdData.cvss_base_score;
        var cvss_vector = nvdData.cvss_vector;

        // insert to sn_vul_nvd_entry
        var nvd = new GlideRecord("sn_vul_nvd_entry");
        var nvdExist = nvd.get("id", name);
        if (!nvdExist) {
            nvd.initialize();
            nvd.setValue("id", name);
            nvd.setValue("summary", url);
            nvd.setValue("v3_base_score", cvss_base_score);
            nvd.setValue("v3_attack_vector", cvss_vector);
            nvd.setValue("source", "Checkmarx One");
            nvd.setValue("integration_run", this.integrationProcessGr.integration_run + "");
            nvdExist = nvd.insert();
        }
    },
    type: 'CheckmarxOneAppVulItemProcessor'
});