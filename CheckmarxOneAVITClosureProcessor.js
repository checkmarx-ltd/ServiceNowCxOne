var CheckmarxOneAVITClosureProcessor = Class.create();
CheckmarxOneAVITClosureProcessor.prototype = Object.extendsObject(sn_vul.ApplicationVulnerabilityImportProcessorBase, {
    MSG: 'CheckmarxOneAVITClosureProcessor:',
    UTIL: new x_chec3_chexone.CheckmarxOneUtil(),

    process: function (attachment) {
        if (!attachment) {
            gs.warn(this.MSG + ' Called with no attachment');
            return;
        }

        try {
            var content = new GlideSysAttachment().getContent(attachment);
            this.UTIL.validateXML(content, 'error');

            var xmlDoc = new XMLDocument2();
            xmlDoc.parseXML(content);

            var scansNode = xmlDoc.getNode("/latestscanreport/xml/scans");
            if (!scansNode) {
                gs.error(this.MSG + " No <scans> node found in XML");
                return;
            }

            var iter = scansNode.getChildNodeIterator();
            var errorProcess = '';

            while (iter.hasNext()) {
                try {
                    var scanNode = iter.next();
                    var data = this._extractScanNodeData(scanNode);

                    var scanId = data.id;
                    var appId = data.app_id;
                    var branch = data.branch;
                    var enginesStr = data.engines;

                    if (!scanId || !appId) {
                        gs.warn(this.MSG + " Missing scanId or appId in <scan> element");
                        continue;
                    }
                    var config = this.UTIL._getConfig('1234');
                    var scan_synchronization = config.scan_synchronization;
                    this._handleFixedAVIT(scanId, appId, branch, scan_synchronization, enginesStr);

                } catch (ex) {
                    gs.error(this.MSG + " Error processing scan node: " + ex);
                    errorProcess += " | " + ex.message;
                }
            }

            if (errorProcess.length > 0) {
                gs.error(this.MSG + " Errors occurred during processing scans: " + errorProcess);
            }

            this.completeProcess(this.integrationProcessGr, this.import_counts);

        } catch (ex) {
            gs.error(this.MSG + " Error validating or parsing the XML: " + ex);
            throw ex;
        }
    },

    _extractScanNodeData: function (scanNode) {
        var data = {};
        var childIter = scanNode.getChildNodeIterator();

        while (childIter.hasNext()) {
            var child = childIter.next();
            var nodeName = child.getNodeName();
            var text = '';

            var textIter = child.getChildNodeIterator();
            while (textIter.hasNext()) {
                var textNode = textIter.next();
                if (textNode.getNodeValue) {
                    text += textNode.getNodeValue();
                }
            }

            data[nodeName] = String(text || '').trim();
        }

        return data;
    },

    _handleFixedAVIT: function (source_scan_id, projectId, branch, scan_synchronization, engines) {
        var engineList = engines.split(",");
        var selectedEngine = [];
        var includesca = this.UTIL.importScaFlaw(this.IMPLEMENTATION);
        var includesast = this.UTIL.importSastFlaw(this.IMPLEMENTATION);
        var includekics = this.UTIL.importKicsFlaw(this.IMPLEMENTATION);
        var includeContainerSecurity = this.UTIL.importContainerSecurityFlaw(this.IMPLEMENTATION);
        var includeSecretDetection = this.UTIL.importSecretDetectionFlaw(this.IMPLEMENTATION);
        var includeScoreCard = this.UTIL.importScoreCardFlaw(this.IMPLEMENTATION);
        var includeApiSecurity = this.UTIL.importApiSecurityFlaw(this.IMPLEMENTATION);

        // Insert values into selectedEngine based on conditions
        if (includesca) selectedEngine.push("sca");
        if (includesast) selectedEngine.push("sast");
        if (includekics) selectedEngine.push("IaC");
        if (includeContainerSecurity) selectedEngine.push("CS");
        if (includeSecretDetection) selectedEngine.push("SecretDetection");
        if (includeScoreCard) selectedEngine.push("Scorecard");
        if (includeApiSecurity) selectedEngine.push("apisec");

        // Step 3: Create finalEngine array with common values between engineList and selectedEngine
        var finalEngine = [];

        // Loop through engineList and check if the value exists in selectedEngine using indexOf
        for (var j = 0; j < engineList.length; j++) {
            if (selectedEngine.indexOf(engineList[j]) !== -1) { // indexOf returns -1 if not found
                finalEngine.push(engineList[j]);
            }
        }

        for (var i = 0; i < finalEngine.length; i++) {
            var avit = new sn_vul.PagedGlideRecord('sn_vul_app_vulnerable_item');
            if (scan_synchronization == 'latest scan from each branch' && (branch != null || branch != '' || branch != '.unknown' || branch != 'undefined')) {
                avit.addEncodedQuery('application_release.source_app_id=' + GlideStringUtil.escapeQueryTermSeparator(projectId) + '^app_vul_scan_summaryNOT LIKE' + GlideStringUtil.escapeQueryTermSeparator(source_scan_id) +
                    '^state!=3^project_branch=' + GlideStringUtil.escapeQueryTermSeparator(branch) + '^app_vul_scan_summarySTARTSWITH' +
                    GlideStringUtil.escapeQueryTermSeparator(finalEngine[i]));
            } else {
                avit.addEncodedQuery('application_release.source_app_id=' + GlideStringUtil.escapeQueryTermSeparator(projectId) + '^app_vul_scan_summaryNOT LIKE' + GlideStringUtil.escapeQueryTermSeparator(source_scan_id) + '^state!=3' + '^app_vul_scan_summarySTARTSWITH' + GlideStringUtil.escapeQueryTermSeparator(finalEngine[i]));
            }
            avit.setSortField("sys_id");
            while (avit.next()) {
                avit.gr.setValue('source_remediation_status', 'FIXED');
                avit.gr.setValue('state', 3);
                avit.gr.update('substate', 4);
            }
        }
    },


    type: 'CheckmarxOneAVITClosureProcessor'
});