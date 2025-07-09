var CheckmarxOneScanSummaryDetailsJSONProcessor = Class.create();
CheckmarxOneScanSummaryDetailsJSONProcessor.prototype = Object.extendsObject(sn_vul.ApplicationVulnerabilityImportProcessorBase, {

    UTIL: new x_chec3_chexone.CheckmarxOneUtil(),
    processRecord: function(sourceGr) {

        var data = {};
        //map attributes from CheckmarxOne into the servicenow scan summary table
        data['source_app_id'] = sourceGr.u_projectid + "";
        data['source_scan_id'] = sourceGr.u_id + "";
        data['name'] = sourceGr.u_projectname + "";
        data['app_name'] = sourceGr.u_projectname + "";
        data['last_scan_date'] = this.UTIL.parseDate(sourceGr.u_updatedat);
        //data['last_scan_date'] = new GlideDateTime(sourceGr.u_updatedat);
        data['detected_flaw_count'] = +sourceGr.u_totalvulnerabilities;
        data['scan_summary_name'] = sourceGr.u_id + ' ' + data['last_scan_date'];
        var query = JSON.parse(sourceGr.u_query + "");
        data['scan_summary_details'] = query;
        var summaryId = this._upsert(data);
        this.postProcessRecord(summaryId);
        this.completeProcess(this.integrationProcessGr, this.import_counts);
    },

    postProcessRecord: function(summaryId) {
        this._getLatestProcessRecord();

        var parameters = JSON.parse(this.PROCESS_GR.getValue('parameters'));
        var currentParameters = parameters.run;

        var devopsRunGr = new GlideRecord('sn_vul_devops_integration_run');
        devopsRunGr.addQuery('sys_id', currentParameters.sysId);
        devopsRunGr.query();

        if (devopsRunGr.next()) {
            if (gs.nil(summaryId)) {
                devopsRunGr.setValue('state', 'complete');
                devopsRunGr.setValue('substate', 'failed');
                devopsRunGr.update();
            } else {
                devopsRunGr.setValue('state', 'complete');
                devopsRunGr.setValue('substate', 'success');
                devopsRunGr.setValue('scan_summary', summaryId);
                devopsRunGr.update();
            }
        }
    },

    _getLatestProcessRecord: function() {
        var processGr = new GlideRecord('sn_vul_integration_process');
        processGr.addQuery('sys_id', this.PROCESS_ID);
        processGr.query();
        processGr.next();
        this.PROCESS_GR = processGr;
    },

    _upsert: function(data) {
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

            var summaryId = result.summaryId;

            var summaryDetails = data.scan_summary_details;
            for (i = 0; i < summaryDetails.length; i++)
                this.AVR_API.createOrUpdateSummaryDetails(summaryDetails[i], summaryId);
        } catch (err) {
            gs.error(this.MSG + " _upsert : Error while inserting data into ServiceNow DB." + err);
            throw err;
        }
        return summaryId;
    },

    type: 'CheckmarxOneScanSummaryDetailsJSONProcessor'
});