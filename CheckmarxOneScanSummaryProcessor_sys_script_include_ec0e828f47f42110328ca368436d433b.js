var CheckmarxOneScanSummaryProcessor = Class.create();
CheckmarxOneScanSummaryProcessor.prototype = Object.extendsObject(sn_vul.ApplicationVulnerabilityImportProcessorBase, {
    MSG: 'CheckmarxOne Scan Summary Processor: ',
    UTIL: new x_chec3_chexone.CheckmarxOneUtil(),

    process: function (attachment) {
        if (attachment) {
            try {
                this.UTIL.validateXML(new GlideSysAttachment().getContent(attachment), 'error');
                var doc = new XMLDocument2();
                doc.parseXML(new GlideSysAttachment().getContent(attachment));
                var node = doc.getNode('/scanData');
                var engine = '';
                if (node.toString().indexOf("sastScanData") != -1) {
                    var sastnodes = doc.getNode('/scanData/sastScanData/scans');
                }
                if (node.toString().indexOf("scaScanData") != -1) {
                    var scanodes = doc.getNode('/scanData/scaScanData/scans');
                }
                if (node.toString().indexOf("kicsScanData") != -1) {
                    var kicsnodes = doc.getNode('/scanData/kicsScanData/scans');
                }
                if (node.toString().indexOf("conSecScanData") != -1) {
                    var containerSecurityNodes = doc.getNode('/scanData/conSecScanData/scans');
                    engine += 'CS, ';
                }
                if (node.toString().indexOf("apiSecScanData") != -1) {
                    var apiSecNodes = doc.getNode('/scanData/apiSecScanData/scans');
                }
                if (node.toString().indexOf("scoreCardScanData") != -1) {
                    var scoreCardNodes = doc.getNode('/scanData/scoreCardScanData/scans');
                }
                if (node.toString().indexOf("secretDetectionScanData") != -1) {
                    var secretDetectionNodes = doc.getNode('/scanData/secretDetectionScanData/scans');
                }

            } catch (ex) {
                gs.error(this.MSG + "Error occurred while validating or parsing the XML: " + ex);
                throw ex;
            }
            var errorProcess = '';
            if (sastnodes) {
                var sastdata = {};
                var iteration = sastnodes.getChildNodeIterator();
                while (iteration.hasNext()) {
                    try {
                        var SastappNode = iteration.next();
                        var Sastattributes = SastappNode.getAttributes();
                        //map attributes from CheckmarxOne into the servicenow scan summary table
                        sastdata['source_app_id'] = Sastattributes.app_id;
                        sastdata['source_scan_id'] = Sastattributes.id;
                        sastdata['detected_flaw_count'] = +Sastattributes.total_no_flaws;
                        sastdata['last_scan_date'] = new GlideDateTime(Sastattributes.last_scan_date);
                        sastdata['scan_summary_name'] = Sastattributes.id + ' ' + sastdata['last_scan_date'];
                        sastdata['scan_analysis_size'] = +Sastattributes.loc;
                        sastdata['policy'] = Sastattributes.engine;
                        sastdata['source_sdlc_status'] = Sastattributes.scan_id;
                        sastdata['tags'] = "Branch: " + Sastattributes.branch;
                        sastdata['scan_submitted_by'] = 'Scan Origin: ' + Sastattributes.scan_origin + '\n' + 'Scan Source: ' + Sastattributes.scan_source + '\n' + 'Scan Type: ' + Sastattributes.scan_type + '\n';
                        this._upsert(sastdata);
                    } catch (ex) {
                        errorMessage = gs.getMessage("Error in retriving data for scan list integration!");
                        gs.error(this.MSG + "errorMessage " + ex);
                        errorProcess += " | " + ex.getMessage();
                        //throw ex;
                    }
                }
            }
            if (scanodes) {
                var data = {};
                var iter = scanodes.getChildNodeIterator();
                while (iter.hasNext()) {
                    try {
                        var appNode = iter.next();
                        var attributes = appNode.getAttributes();
                        //map attributes from Checkmarx into the servicenow scan summary table
                        data['source_app_id'] = attributes.app_id;
                        data['source_scan_id'] = attributes.id;
                        data['detected_flaw_count'] = +attributes.total_no_flaws;
                        data['last_scan_date'] = new GlideDateTime(attributes.last_scan_date);
                        data['scan_summary_name'] = attributes.id + ' ' + data['last_scan_date'];
                        data['policy'] = attributes.engine;
                        data['source_sdlc_status'] = attributes.scan_id;
                        data['tags'] = "Branch: " + attributes.branch;
                        data['scan_submitted_by'] = 'Scan Origin: ' + attributes.scan_origin + '\n' + 'Scan Source: ' + attributes.scan_source + '\n' + 'Scan Type: ' + attributes.scan_type + '\n';
                        this._upsert(data);
                    } catch (ex) {
                        errorMessage = gs.getMessage("Error in retriving data for scan list integration!");
                        gs.error(this.MSG + "errorMessage " + ex);
                        errorProcess += " | " + ex.getMessage();
                        //throw ex;
                    }
                }
            }
            if (kicsnodes) {
                var kicsdata = {};
                var kicsiteration = kicsnodes.getChildNodeIterator();
                while (kicsiteration.hasNext()) {
                    try {
                        var kicsappNode = kicsiteration.next();
                        var kicsattributes = kicsappNode.getAttributes();
                        //map attributes from CheckmarxOne into the servicenow scan summary table
                        kicsdata['source_app_id'] = kicsattributes.app_id;
                        kicsdata['source_scan_id'] = kicsattributes.id;
                        kicsdata['detected_flaw_count'] = +kicsattributes.total_no_flaws;
                        kicsdata['last_scan_date'] = new GlideDateTime(kicsattributes.last_scan_date);
                        kicsdata['scan_summary_name'] = kicsattributes.id + ' ' + kicsdata['last_scan_date'];
                        kicsdata['policy'] = kicsattributes.engine;
                        kicsdata['source_sdlc_status'] = kicsattributes.scan_id;
                        kicsdata['tags'] = "Branch: " + kicsattributes.branch;
                        kicsdata['scan_submitted_by'] = 'Scan Origin: ' + kicsattributes.scan_origin + '\n' + 'Scan Source: ' + kicsattributes.scan_source + '\n' + 'Scan Type: ' + kicsattributes.scan_type + '\n';
                        this._upsert(kicsdata);
                    } catch (ex) {
                        errorMessage = gs.getMessage("Error in retriving data for scan list integration!");
                        gs.error(this.MSG + "errorMessage " + ex);
                        errorProcess += " | " + ex.getMessage();
                        //throw ex;
                    }
                }
            }
            if (containerSecurityNodes) {
                var conSecData = {};
                var conSecIteration = containerSecurityNodes.getChildNodeIterator();
                while (conSecIteration.hasNext()) {
                    try {
                        var conSecAppNode = conSecIteration.next();
                        var conSecAttributes = conSecAppNode.getAttributes();
                        //map attributes from CheckmarxOne into the servicenow scan summary table
                        conSecData['source_app_id'] = conSecAttributes.app_id;
                        conSecData['source_scan_id'] = conSecAttributes.id;
                        conSecData['detected_flaw_count'] = +conSecAttributes.total_no_flaws;
                        conSecData['last_scan_date'] = new GlideDateTime(conSecAttributes.last_scan_date);
                        conSecData['scan_summary_name'] = conSecAttributes.id + ' ' + conSecData['last_scan_date'];
                        conSecData['policy'] = conSecAttributes.engine;
                        conSecData['source_sdlc_status'] = conSecAttributes.scan_id;
                        conSecData['tags'] = "Branch: " + conSecAttributes.branch;
                        conSecData['scan_submitted_by'] = 'Scan Origin: ' + conSecAttributes.scan_origin + '\n' + 'Scan Source: ' + conSecAttributes.scan_source + '\n' + 'Scan Type: ' + conSecAttributes.scan_type + '\n';
                        this._upsert(conSecData);
                    } catch (ex) {
                        errorMessage = gs.getMessage("Error in retriving data for scan list integration!");
                        gs.error(this.MSG + "errorMessage " + ex);
                        errorProcess += " | " + ex.getMessage();
                        //throw ex;
                    }
                }
            }
            if (apiSecNodes) {
                var apiSecData = {};
                var apiSecIteration = apiSecNodes.getChildNodeIterator();
                while (apiSecIteration.hasNext()) {
                    try {
                        var apiSecAppNode = apiSecIteration.next();
                        var apiSecAttributes = apiSecAppNode.getAttributes();
                        // Map API Security attributes
                        apiSecData['source_app_id'] = apiSecAttributes.app_id;
                        apiSecData['source_scan_id'] = apiSecAttributes.id;
                        apiSecData['detected_flaw_count'] = +apiSecAttributes.total_no_flaws;
                        apiSecData['last_scan_date'] = new GlideDateTime(apiSecAttributes.last_scan_date);
                        apiSecData['scan_summary_name'] = apiSecAttributes.id + ' ' + apiSecData['last_scan_date'];
                        apiSecData['policy'] = apiSecAttributes.engine;
                        apiSecData['source_sdlc_status'] = apiSecAttributes.scan_id;
                        apiSecData['tags'] = "Branch: " + apiSecAttributes.branch;
                        apiSecData['scan_submitted_by'] = 'Scan Origin: ' + apiSecAttributes.scan_origin + '\n' + 'Scan Source: ' + apiSecAttributes.scan_source + '\n' + 'Scan Type: ' + apiSecAttributes.scan_type + '\n';
                        this._upsert(apiSecData);
                    } catch (ex) {
                        errorMessage = gs.getMessage("Error processing API Security scan data!");
                        gs.error(this.MSG + errorMessage + " " + ex);
                        errorProcess += " | " + ex.getMessage();
                    }
                }
            }
            if (scoreCardNodes) {
                var scoreCardData = {};
                var scoreCardIteration = scoreCardNodes.getChildNodeIterator();
                while (scoreCardIteration.hasNext()) {
                    try {
                        var scoreCardAppNode = scoreCardIteration.next();
                        var scoreCardAttributes = scoreCardAppNode.getAttributes();
                        //map attributes from CheckmarxOne into the servicenow scan summary table
                        scoreCardData['source_app_id'] = scoreCardAttributes.app_id;
                        scoreCardData['source_scan_id'] = scoreCardAttributes.id;
                        scoreCardData['detected_flaw_count'] = +scoreCardAttributes.total_no_flaws;
                        scoreCardData['last_scan_date'] = new GlideDateTime(scoreCardAttributes.last_scan_date);
                        scoreCardData['scan_summary_name'] = scoreCardAttributes.id + ' ' + scoreCardData['last_scan_date'];
                        scoreCardData['policy'] = scoreCardAttributes.engine;
                        scoreCardData['source_sdlc_status'] = scoreCardAttributes.scan_id;
                        scoreCardData['tags'] = "Branch: " + scoreCardAttributes.branch;
                        scoreCardData['scan_submitted_by'] = 'Scan Origin: ' + scoreCardAttributes.scan_origin + '\n' + 'Scan Source: ' +
                            scoreCardAttributes.scan_source + '\n' + 'Scan Type: ' + scoreCardAttributes.scan_type + '\n';
                        this._upsert(scoreCardData);
                    } catch (ex) {
                        errorMessage = gs.getMessage("Error in retriving data for scan list integration!");
                        gs.error(this.MSG + "errorMessage " + ex);
                        errorProcess += " | " + ex.getMessage();
                        //throw ex;
                    }
                }
            }
            if (secretDetectionNodes) {
                var secretDetectionData = {};
                var secretDetectionIteration = secretDetectionNodes.getChildNodeIterator();
                while (secretDetectionIteration.hasNext()) {
                    try {
                        var secretDetectionAppNode = secretDetectionIteration.next();
                        var secretDetectionAttributes = secretDetectionAppNode.getAttributes();
                        //map attributes from CheckmarxOne into the servicenow scan summary table
                        secretDetectionData['source_app_id'] = secretDetectionAttributes.app_id;
                        secretDetectionData['source_scan_id'] = secretDetectionAttributes.id;
                        secretDetectionData['detected_flaw_count'] = +secretDetectionAttributes.total_no_flaws;
                        secretDetectionData['last_scan_date'] = new GlideDateTime(secretDetectionAttributes.last_scan_date);
                        secretDetectionData['scan_summary_name'] = secretDetectionAttributes.id + ' ' + secretDetectionAttributes['last_scan_date'];
                        secretDetectionData['policy'] = secretDetectionAttributes.engine;
                        secretDetectionData['source_sdlc_status'] = secretDetectionAttributes.scan_id;
                        secretDetectionData['tags'] = "Branch: " + secretDetectionAttributes.branch;
                        secretDetectionData['scan_submitted_by'] = 'Scan Origin: ' + secretDetectionAttributes.scan_origin + '\n' + 'Scan Source: ' +
                            secretDetectionAttributes.scan_source + '\n' + 'Scan Type: ' + secretDetectionAttributes.scan_type + '\n';
                        this._upsert(secretDetectionData);
                    } catch (ex) {
                        errorMessage = gs.getMessage("Error in retriving data for scan list integration!");
                        gs.error(this.MSG + "errorMessage " + ex);
                        errorProcess += " | " + ex.getMessage();
                        //throw ex;
                    }
                }
            }

            if (!gs.nil(errorProcess))
                gs.error(this.MSG + "All errors that occurred while processing scan summary: " + errorProcess);
            this.completeProcess(this.integrationProcessGr, this.import_counts);

        } else
            gs.warn(this.MSG + ':process called with no attachment');
    },


    _parseStatic: function (node, data) {
        try {
            this._handleScanType(node, data, 'last_static_scan_date');
        } catch (err) {
            gs.error(this.MSG + " _parseStatic : Error while parsing the date and rating field.");
            throw err;
        }
    },

    _handleScanType: function (node, data, dateField) {
        try {
            data[dateField] = new GlideDateTime(node.getAttribute('last_scan_date'));
            if (gs.nil(data['last_scan_date']) >= data['last_scan_date']) {
                data['last_scan_date'] = data[dateField];
            }
        } catch (err) {
            gs.error(this.MSG + " _handleScanType : Error while handling scan type.");
            throw err;
        }
    },

    _upsert: function (data) {
        try {
            var result = this.AVR_API.createOrUpdateSummary(data);
            if (!result)
                return;
            if (result.updated)
                this.import_counts.updated++;
            else if (result.inserted)
                this.import_counts.inserted++;
            else if (result.unchanged)
                this.import_counts.unchanged++;
        } catch (err) {
            gs.error(this.MSG + " _upsert : Error while inserting data into ServiceNow DB.");
            throw err;
        }
    },
    type: 'CheckmarxOneScanSummaryProcessor'
});