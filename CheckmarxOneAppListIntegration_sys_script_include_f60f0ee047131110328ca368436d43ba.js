var CheckmarxOneAppListIntegration = Class.create();
CheckmarxOneAppListIntegration.prototype = Object.extendsObject(sn_vul.ApplicationVulnerabilityIntegrationBase, {


    UTIL: new CheckmarxOneUtil(),
    MSG: 'CheckmarxOne AppListIntegration:',
    retrieveData: function() {
        gs.debug(this.MSG + 'retrieveData');
        var response = "<null/>";
        try {
            var params = this._getParameters(this.PROCESS.getValue('parameters'));

            if (params.run) {
                //  filteredcount,  offset
                response = this.getAppList(Object.keys(params.run)[0], params.run[Object.keys(params.run)[0]]);
            }

        } catch (ex) {
            gs.error(this.MSG + "Error in retriving data for app list integration!" + ex);
            response = '<appInfoList><xml id="checkmarxone"><projects></projects></xml></appInfoList>';

        }
        if (response == "<null/>") {
            response = '<appInfoList><xml id="checkmarxone"><projects></projects></xml></appInfoList>';

        }

        if (response == -1) {
            params.run == false;
            this.hasMoreData(false);
            response = '<appInfoList><xml id="checkmarxone"><projects></projects></xml></appInfoList>';
            var latest_date = new GlideDateTime();
            this.INTEGRATION.setValue('delta_start_time', latest_date);
            this.INTEGRATION.update();
        } else {
            params = this._serializeParameters(this._nextParameters(params));
            this.setNextRunParameters(params);
        }

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

    //Creates XML summary for Projects
    getAppList: function(filteredCount, offset) {
        try {
            var config = this.UTIL._getConfig(this.IMPLEMENTATION);
            var appListRootNodeStart = "<appInfoList><xml id=\"checkmarxone\"><projects>";
            var appListRootNodeEnd = "</projects></xml></appInfoList>";
            var appListAll = '';
            //to start offset from 0 and config.limit 
            var newoffset = offset - config.limit;
            var projects = this.UTIL.getNextProjectList(this.IMPLEMENTATION, newoffset);
            var groups = '';
            var groupval = ' ';
            var createdDate = this._getCurrentDeltaStartTime();

            for (var item in projects) {
                if (projects[item].createdAt > createdDate) {
                    var projectTags = this._getProjectTags(JSON.stringify(projects[item].tags));
                    var applicationIds = '';
                    var primaryBranch = '';
                    groups = +projects[item].groups.toString();

                    if (null != projects[item].applicationIds && projects[item].applicationIds.length > 0)
                        applicationIds = projects[item].applicationIds.toString();
                    if (null != projects[item].mainBranch && projects[item].mainBranch.length > 0)
                        primaryBranch = projects[item].mainBranch.toString();

                    var currentGroupVal = (groups.length == 0) ? groupval : projects[item].groups.toString();

                    appListAll += '<project id="' + this.UTIL.escapeXmlChars(projects[item].id) + '"' +
                        ' createdAt="' + this.UTIL.escapeXmlChars(projects[item].createdAt) + '"' +
                        ' applicationIds="' + this.UTIL.escapeXmlChars(applicationIds) + '"' +
                        ' groups="' + this.UTIL.escapeXmlChars(currentGroupVal) + '">' +
                        '<primaryBranch>' + this.UTIL.escapeCDATA(primaryBranch) + '</primaryBranch>' +
                        '<projectTags>' + this.UTIL.escapeCDATA(projectTags) + '</projectTags>' +
                        '<name>' + this.UTIL.escapeCDATA(projects[item].name) + '</name>' +
                        '</project>';

                }
                if (appListAll == '' && createdDate > projects[item].createdAt) {
                    return -1;
                }
            }

            var reportContent = appListRootNodeStart + appListAll + appListRootNodeEnd;
        } catch (err) {
            gs.error(this.MSG + " getAppList : Error occured while creating XML for project list: " + err);
            throw err;
        }
        return reportContent;
    },

    _getProjectTags: function(tags) {
        if (tags == null || tags.length < 3)
            return '';
        return tags.substring(1, tags.length - 1);
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
                this.LATEST = new GlideDateTime();
                var offsetId;
                var filteredCount;
                var filter_project = this.UTIL._getConfig(this.IMPLEMENTATION).filter_project;
                var list_projects = this.UTIL.getConfigProjectList(this.IMPLEMENTATION);
                if (list_projects && list_projects.length > 0 && list_projects.indexOf('exclude') == -1 && filter_project == 'by_Id') {
                    var projectLengthUI = '' + list_projects.length;
                    offsetId = this._getoffsets(projectLengthUI, projectLengthUI);
                    filteredCount = projectLengthUI;
                } else {
                    var projectJSON = this.UTIL.getNewProjectList(this.IMPLEMENTATION);
                    filteredCount = projectJSON.filteredTotalCount;
                    var totalCount = projectJSON.totalCount;
                    if (filteredCount !== "undefined") {
                        offsetId = this._getoffsets(filteredCount, totalCount);
                    }
                }
                params.remaining[filteredCount] = offsetId;
                gs.debug(this.MSG + 'for appreleases complete');
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
    //to get offset value from total length
    _getoffsets: function(filteredCount, totalCount) {
        var config = this.UTIL._getConfig(this.IMPLEMENTATION);
        var limit = config.limit;
        var offsets = [];
        var loopLength = totalCount / limit;
        var offset = 0;
        for (var i = 0; i <= parseInt(loopLength); i++) {
            offset += limit;
            var offsetId = this._getoffset(filteredCount, offset);
            if (offsetId) {
                offsets.push(offsetId);
                var date = new GlideDateTime();
            }
        }
        //returning offset from of limit instead of 0 because remaining value in run will throw error if 0 is passed.
        return offsets;
    },

    _getoffset: function(config, offsetId) {
        return offsetId;
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
            var offsets = [];
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
    type: 'CheckmarxOneAppListIntegration'
});