var CheckmarxOneUtilBase = Class.create();

CheckmarxOneUtilBase.prototype = {
    SEC_UTIL: new sn_sec_cmn.SecCommonUtil(),
    MSG: 'CheckmarxOneUtilBase:',
    initialize: function() {},

    //get all project list
    getProjectList: function(configId) {
        try {
            var request = new sn_ws.RESTMessageV2();
            var config = this._getConfig(configId);
            var baseUrl = config.checkmarxone_server_url;
            var apiurl = config.checkmarxone_api_base_url;
            var method = "post";
            var query = '/api/projects';
            var token = this.getAccessToken(baseUrl, config, method, request, configId);
        } catch (err) {
            gs.error(this.MSG + " getProjectList : Error while getting the project list." + err);
            throw err;
        }
        return this._makeRestApiCall(apiurl, configId, token, query, "get");
    },

    //get one project from project list for pre Validation
    getProjectListForValidation: function(config) {
        try {
            var request = new sn_ws.RESTMessageV2();
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var method = "post";
            var configId = "1234";
            var save_token_flag = "false";
            var token = this.getNewToken(accesscontrolbaseUrl, config, method, request, config.client_id, config.client_secret, config.tenant, save_token_flag, configId);
            var query = '/api/projects/?offset=0&limit=1';
        } catch (err) {
            gs.error(this.MSG + " getProjectListForValidation: Error while getting project for validation." + err);
            throw err;
        }
        return this._makeRestCall(apibaseurl, configId, token, query, "get");
    },

    //get one project from project list
    getProject: function(configId) {
        try {
            var request = new sn_ws.RESTMessageV2();
            var config = this._getConfig(configId);
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var method = "post";
            var save_token_flag = "true";
            var token = this.getNewTokenForValidation(accesscontrolbaseUrl, config, method, request, config.client_id, config.client_secret, config.tenant, save_token_flag, configId);
            var query = '/api/projects/?offset=0&limit=1';
        } catch (err) {
            gs.error(this.MSG + " getProject: Error while getting project." + err);
            throw err;
        }
        return this._makeRestApiCall(apibaseurl, configId, token, query, "get");
    },

    //get all project list
    getProjects: function(configId) {
        var projectJson = '';
        try {
            var request = new sn_ws.RESTMessageV2();
            var config = this._getConfig(configId);
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var method = "post";
            var save_token_flag = "true";
            var token = this.getNewToken(accesscontrolbaseUrl, config, method, request, config.client_id, config.client_secret, config.tenant, save_token_flag, configId);

            // Use the pagination helper
            var baseQuery = '/api/projects/';
            projectJson = this._makePaginatedApiCall(apibaseurl, configId, token, baseQuery, "get", 'projects');

        } catch (err) {
            gs.error(this.MSG + " getProjects: Error while getting projects." + err);
            throw err;
        }
        return projectJson;
    },

    //get ProjectId and Primary Branch list
    getProjectPrimaryBranchList: function(configId) {
        var projectPrimaryBranchList = [];
        try {
            var projectJson = this.getProjects(configId);
            for (var item in projectJson.projects) {
                var id = projectJson.projects[item].id;
                var mainBranch = projectJson.projects[item].mainBranch;
                if (null != mainBranch && mainBranch != "") {
                    var projectPrimaryBranch = id + ':' + mainBranch;
                    projectPrimaryBranchList.push(projectPrimaryBranch);
                }
            }
        } catch (err) {
            gs.error(this.MSG + ' getProjectPrimaryBranchList: error while getting project primary branch list.');
        }
        return projectPrimaryBranchList;
    },

    //get Primary Branch By projectId
    getPrimaryBranchByProjectId: function(projectPrimaryBranchList, projectId) {
        var primaryBranch = '';
        for (var item in projectPrimaryBranchList) {
            var primaryBranchWithProjectId = projectPrimaryBranchList[item];
            if (primaryBranchWithProjectId.indexOf(projectId) != -1) {
                primaryBranch = primaryBranchWithProjectId.split(':')[1];
                break;
            }
        }
        return primaryBranch;
    },

    //get new project list
    getNewProjectList: function(configId) {
        try {
            var request = new sn_ws.RESTMessageV2();
            var config = this._getConfig(configId);
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var method = "post";
            var query = '';
            var token = this.getAccessToken(accesscontrolbaseUrl, config, method, request, configId);
            query = '/api/projects/?offset=0&limit=1';
            var resp = this._makeRestApiCall(apibaseurl, configId, token, query, "get");
            var body = resp.getBody();
            var projectJSON = JSON.parse(body);
        } catch (err) {
            gs.error(this.MSG + " getNewProjectList: Error while getting the project list: " + err);
            throw err;
        }
        return projectJSON;
    },

    //To get Lists of project from Configuration Page
    getConfigProjectList: function(configId) {
        try {
            var config = this._getConfig(configId);
            var project_lists = [];
            var list_projects = config.list_of_project_id_s;
            if (list_projects && list_projects.length > 0) {
                var list_project_arr = list_projects.replace("=", ";").split(";");
                for (var id in list_project_arr) {
                    var projectId = list_project_arr[id].trim();
                    if (projectId && projectId.length > 0 && project_lists.indexOf(projectId) == -1)
                        project_lists.push(projectId);
                }
            }
        } catch (err) {
            gs.error(this.MSG + " getConfigProjectList: Error while getting project IDs from config." + err);
            throw err;
        }
        return project_lists;
    },

    //To get the list of project name from Configuration Page
    getConfigProjectNameList: function(configId) {
        try {
            var config = this._getConfig(configId);
            var project_name_lists = [];
            var list_project_name = config.project_filter_by_name;
            if (list_project_name && list_project_name.length > 0) {
                var list_project_name_arr = list_project_name.replace("=", ";").split(";");
                for (var id in list_project_name_arr) {
                    var projectName = list_project_name_arr[id].trim();
                    if (projectName && projectName.length > 0 && project_name_lists.indexOf(projectName) == -1)
                        project_name_lists.push(projectName);
                }
            }
        } catch (err) {
            gs.error(this.MSG + " getConfigProjectNameList: Error while getting project name from config." + err);
            throw err;
        }
        return project_name_lists;
    },

    //get Project By Id
    getConfigProjectById: function(configId, projectId) {
        try {
            var request = new sn_ws.RESTMessageV2();
            var config = this._getConfig(configId);
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var method = "post";
            var token = this.getAccessToken(accesscontrolbaseUrl, config, method, request, configId);
            var query = '/api/projects/' + projectId;
            var resp = this._makeConfigRestApiCall(apibaseurl, configId, token, query, "get");
        } catch (err) {
            gs.error(this.MSG + " getConfigProjectById: Error while getting the details of project present in config." + err);
        }
        return resp;
    },

    // To Get Result state from configuartion	
    getResultStateFromUI: function(configId) {
        try {
            var config = this._getConfig(configId);
            var resultState = config.result_states;
            var result_state = [];
            var resultStateUIArr = resultState.split(',');
            for (var item in resultStateUIArr) {
                result_state.push(resultStateUIArr[item]);
            }

        } catch (err) {
            gs.error(this.MSG + " getResultStateFromUI: Error while getting Result State from Configuration " + err);
        }
        return JSON.stringify(result_state);
    },

    // To get API Security vulnerabilities information of scanId based on sast_risk_id
    getApiSecVulInfoBySastRiskId: function(configId, scanId, sastRiskId) {
        try {
            var request = new sn_ws.RESTMessageV2();
            var config = this._getConfig(configId);
            var query = '/api/apisec/static/api/risks/' + scanId + '?filtering=' + encodeURIComponent('[{"column":"sast_risk_id","values": "' + sastRiskId + '","operator":"eq"}]');
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var method = "get";
            var token = this.getAccessToken(accesscontrolbaseUrl, config, method, request, configId);

        } catch (err) {
            gs.error(this.MSG + " getApiSecVulInfo: Error while getting the apisec vul Info: " + err);
            return -1;
        }
        return this._makeRestApiCall(apibaseurl, configId, token, query, "get");

    },

    // To Get Severity from configuartion	
    getSeverityFromUI: function(configId) {
        try {
            var config = this._getConfig(configId);
            var severity = config.severity;
            var severity_list = [];
            var severityUIArr = severity.split(',');
            for (var item in severityUIArr) {
                severity_list.push(severityUIArr[item]);
            }

        } catch (err) {
            gs.error(this.MSG + " getSeverityFromUI: Error while getting Result State from Configuration " + err);
        }
        return JSON.stringify(severity_list);
    },

    //get 50 project list at a time
    getNextProjectList: function(configId, offsetno) {
        var projects = [];
        var list_projects = [];
        var list_projects_name = [];
        try {
            var request = new sn_ws.RESTMessageV2();
            var config = this._getConfig(configId);
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var limit_val = config.limit;
            var method = "post";
            var token = this.getAccessToken(accesscontrolbaseUrl, config, method, request, configId);
            var query = '';
            var projectid = '';
            var filter_project = config.filter_project;
            list_projects = this.getConfigProjectList(configId);
            list_projects_name = this.getConfigProjectNameList(configId);

            if (list_projects && list_projects.length > 0 && list_projects.indexOf('exclude') == -1 && filter_project == 'by_Id') {
                var index = parseInt(offsetno);
                var offsetLength = index + 50;
                if (offsetLength > list_projects.length) {
                    offsetLength = list_projects.length;
                }
                for (var id = index; id < offsetLength; id++) {
                    if (list_projects[id].length > 0) {
                        var projectStatus = this.getConfigProjectById(configId, list_projects[id]);
                        if (projectStatus == 200 || projectStatus == 202)
                            projectid += '&ids=' + list_projects[id];
                        else
                            gs.warn(this.MSG + "Entered project id is not valid: " + list_projects[id]);
                    }
                }
                query = '/api/projects/?limit=' + limit_val + projectid;

            } else {
                query = '/api/projects/?offset=' + offsetno + '&limit=' + limit_val;
            }
            var resp = this._makeRestApiCall(apibaseurl, configId, token, query, "get");
            var body = resp.getBody();
            var projectJSON = JSON.parse(body);


            if (list_projects_name && list_projects_name.length > 0 && filter_project == 'by_name') {
                var projectIdsByNames = this.getProjectIdsFromProjectNames(configId, list_projects_name);
            }
            for (var item in projectJSON.projects) {
                if (filter_project == 'by_Id' && list_projects && list_projects.length > 0 && list_projects.indexOf('exclude') != -1 && list_projects.indexOf(projectJSON.projects[item].id.toString()) == -1) {
                    try {
                        var not_exclude_project = this.getProjectById(configId, projectJSON.projects[item].id);
                        projects.push(not_exclude_project);
                    } catch (error) {
                        gs.error(this.MSG + " getNextProjectList: Failed to get detail about project Id: " + projectJSON.projects[item].id + " with error: " + error);
                        continue;
                    }
                } else if (filter_project == 'by_Id' && list_projects && list_projects.length > 0 && list_projects.indexOf('exclude') == -1 && list_projects.indexOf(projectJSON.projects[item].id.toString()) != -1) {
                    try {
                        var include_project = this.getProjectById(configId, projectJSON.projects[item].id);
                        projects.push(include_project);
                    } catch (error) {
                        gs.error(this.MSG + " getNextProjectList: Failed to get detail about project Id: " + projectJSON.projects[item].id + " with error: " + error);
                        continue;
                    }
                } else if (filter_project == 'by_name' && list_projects_name && list_projects_name.length > 0 && list_projects_name.indexOf('exclude') != -1 && projectIdsByNames.indexOf(projectJSON.projects[item].id.toString()) == -1) {
                    try {
                        var not_exclude_project_name = this.getProjectById(configId, projectJSON.projects[item].id);
                        projects.push(not_exclude_project_name);
                    } catch (error) {
                        gs.error(this.MSG + " getNextProjectList: Failed to get detail about project Id: " + projectJSON.projects[item].id + " with error: " + error);
                        continue;
                    }
                } else if (filter_project == 'by_name' && list_projects_name && list_projects_name.length > 0 && list_projects_name.indexOf('exclude') == -1 && projectIdsByNames.indexOf(projectJSON.projects[item].id) != -1) {
                    try {
                        var include_project_name = this.getProjectById(configId, projectJSON.projects[item].id);
                        projects.push(include_project_name);
                    } catch (error) {
                        gs.error(this.MSG + " getNextProjectList: Failed to get detail about project Id: " + projectJSON.projects[item].id + " with error: " + error);
                        continue;
                    }
                } else if (filter_project == '' || filter_project == null || filter_project == 'none') {
                    try {
                        var project = this.getProjectById(configId, projectJSON.projects[item].id);
                        projects.push(project);
                    } catch (error) {
                        gs.error(this.MSG + " getNextProjectList: Failed to get detail about project Id: " + projectJSON.projects[item].id + " with error: " + error);
                        continue;
                    }
                }
            }
        } catch (err) {
            gs.error(this.MSG + " getNextProjectList: Error while getting the Project details: " + err);
            throw err;
        }
        return projects;
    },

    //get project Ids from the Config Project Name List
    getProjectIdsFromProjectNames: function(configId, list_projects_name) {
        var projectIds = [];
        try {
            var config = this._getConfig(configId);
            var request = new sn_ws.RESTMessageV2();
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var method = "post";
            var token = this.getAccessToken(accesscontrolbaseUrl, config, method, request, configId);
            var query = '/api/projects/?offset=0&limit=1000&name-regex=';

            var regex = '^.*(';
            for (var id in list_projects_name) {
                if (list_projects_name[id] && null != list_projects_name[id] && '' != list_projects_name[id] && 'undefined' != list_projects_name[id] && list_projects_name[id].indexOf('exclude') == -1) {
                    var escapedProjectName = this.escapeProjectName(list_projects_name[id]);
                    if ((id == 0 && list_projects_name.indexOf('exclude') == -1) || (id == 1 && list_projects_name.indexOf('exclude') != -1))
                        regex += escapedProjectName;
                    else
                        regex += '|' + escapedProjectName;
                }
            }
            regex += ').*$';
            var regex_encode = gs.urlEncode(regex);
            query += regex_encode;
            var resp = this._makeRestApiCall(apibaseurl, configId, token, query, "get");
            var projectJSON = JSON.parse(resp.getBody());
            if (null != projectJSON.projects) {
                for (var item in projectJSON.projects) {
                    var projectId = projectJSON.projects[item].id;
                    projectIds.push(projectId);
                }
            }
        } catch (err) {
            gs.error(this.MSG + " getProjectIdsFromProjectNames: Error while getting the project Ids from project name." + err);
            throw err;
        }
        return projectIds;
    },

    // Escape Special Chars in ProjectName
    escapeProjectName: function(projectName) {
        var escapedProjectName = '';
        var projectNameArr = projectName.split('');

        var specialChars = ['!', '@', '#', '%', '*', '+', '.', '_', '-', ',', '\'', ':', '"', '`', '~', '>', '<', '$', '^', '&', ')', '(', ']', '[', '}', '{', '/', '\\', '|'];

        for (var item in projectNameArr) {
            if (specialChars.indexOf(projectNameArr[item]) != -1)
                escapedProjectName += '\\' + projectNameArr[item];
            else
                escapedProjectName += projectNameArr[item];
        }

        return escapedProjectName;
    },

    //check if project needs to be included or not
    isProjectIncluded: function(configId, filter_project, list_projects, list_projects_name, projectIdsByNames, projectId) {
        var includeProjectFlag = 'true';

        if (filter_project == 'by_Id' && list_projects && list_projects.length > 0 && list_projects.indexOf('exclude') != -1 && list_projects.indexOf(projectId) != -1) {
            includeProjectFlag = 'false';
        } else if (filter_project == 'by_Id' && list_projects && list_projects.length > 0 && list_projects.indexOf('exclude') == -1 && list_projects.indexOf(projectId) == -1) {
            includeProjectFlag = 'false';
        } else if (filter_project == 'by_name' && list_projects_name && list_projects_name.length > 0 && list_projects_name.indexOf('exclude') != -1 && projectIdsByNames.indexOf(projectId) != -1) {
            includeProjectFlag = 'false';
        } else if (filter_project == 'by_name' && list_projects_name && list_projects_name.length > 0 && list_projects_name.indexOf('exclude') == -1 && projectIdsByNames.indexOf(projectId) == -1) {
            includeProjectFlag = 'false';
        } else if (filter_project == '' || filter_project == null || filter_project == 'none') {
            includeProjectFlag = 'true';
        }
        return includeProjectFlag;
    },

    //get Project By Id
    getProjectById: function(configId, projectId) {
        try {
            var request = new sn_ws.RESTMessageV2();
            var config = this._getConfig(configId);
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var method = "post";
            var token = this.getAccessToken(accesscontrolbaseUrl, config, method, request, configId);
            var query = '/api/projects/' + projectId;
            var resp = this._makeRestApiCall(apibaseurl, configId, token, query, "get");
            var body = resp.getBody();
            var projectJSON = JSON.parse(body);

        } catch (err) {
            gs.error(this.MSG + " getProjectById: Error while getting the project info: " + err);
            throw err;
        }
        return projectJSON;
    },

    //get Project Branch List
    getProjectBranchList: function(configId, projectId) {
        try {
            var request = new sn_ws.RESTMessageV2();
            var config = this._getConfig(configId);
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var method = "post";
            var token = this.getAccessToken(accesscontrolbaseUrl, config, method, request, configId);
            var query = '/api/projects/branches?project-id=' + projectId;
            var resp = this._makeRestApiCall(apibaseurl, configId, token, query, "get");
            var body = resp.getBody();
            var projectJSON = JSON.parse(body);

        } catch (err) {
            gs.error(this.MSG + " getProjectBranchList: Error while getting the project info: " + err);
            throw err;
        }
        return projectJSON;
    },

    //get Project By Name
    getProjectByName: function(configId, projectName) {
        try {
            var request = new sn_ws.RESTMessageV2();
            var config = this._getConfig(configId);
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var method = "post";
            var token = this.getAccessToken(accesscontrolbaseUrl, config, method, request, configId);
            var query = '/api/projects/?offset=0&limit=1&name-regex=' + projectName;
            var resp = this._makeRestApiCall(apibaseurl, configId, token, query, "get");
            var body = resp.getBody();
            var projectJSON = JSON.parse(body);

        } catch (err) {
            gs.error(this.MSG + " getProjectByName: Error while getting the project info by project name." + err);
            throw err;
        }
        return projectJSON;
    },

    //List of project IDs from last_run_date
    getprojectScanList: function(configId, last_run_date) {
        var projectIdsByLastScanDate = [];
        try {
            var includesca = this.importScaFlaw(this.IMPLEMENTATION);
            var includesast = this.importSastFlaw(this.IMPLEMENTATION);
            var includekics = this.importKicsFlaw(this.IMPLEMENTATION);
            var includeContainerSecurity = this.importContainerSecurityFlaw(this.IMPLEMENTATION);
            var includeSecretDetection = this.importSecretDetectionFlaw(this.IMPLEMENTATION);
            var includeScoreCard = this.importScoreCardFlaw(this.IMPLEMENTATION);
            var request = new sn_ws.RESTMessageV2();
            var config = this._getConfig(configId);
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var method = "post";
            var token = this.getAccessToken(accesscontrolbaseUrl, config, method, request, configId);

            // Define base query without offset/limit
            var baseQuery = '/api/scans/scansBrief?statuses=Completed&from-date=' + last_run_date + '&sort=-created_at';

            // Use pagination helper
            var scanJson = this._makePaginatedScansApiCall(apibaseurl, configId, token, baseQuery, "get", 'scans');

            // Process the results from the helper function's response
            if (scanJson && scanJson.scans) {
                for (var item in scanJson.scans) {
                    var projectId = scanJson.scans[item].projectId;
                    projectIdsByLastScanDate.push(projectId);
                }
            }
        } catch (err) {
            gs.error(this.MSG + " :getprojectScanList :Error while getting Project list from last scan run date: " + err);
        }
        return projectIdsByLastScanDate;
    },

    //List of scans from last_run_date
    getAllScanList: function(configId, last_run_date) {
        try {
            var request = new sn_ws.RESTMessageV2();
            var config = this._getConfig(configId);
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var method = "post";
            var token = this.getAccessToken(accesscontrolbaseUrl, config, method, request, configId);
            // Define base query without offset/limit
            var baseQuery = '/api/scans/scansBrief?statuses=Completed&from-date=' + last_run_date + '&sort=-created_at';

            // Use pagination helper
            scanJson = this._makePaginatedScansApiCall(apibaseurl, configId, token, baseQuery, "get", 'scans');

        } catch (err) {
            gs.error(this.MSG + " :getAllScanList :Error while getting scans from last run date." + err);
        }

        return scanJson;

    },


    //List of scanIds for a given app/project filter by branch name
    getScanListFilterByBranch: function(configId, projectId, last_run_date, branch) {
        try {
            var request = new sn_ws.RESTMessageV2();
            var config = this._getConfig(configId);
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var method = "post";
            var token = this.getAccessToken(accesscontrolbaseUrl, config, method, request, configId);
            var query = '/api/scans/?offset=0&limit=1&statuses=Completed&project-id=' + projectId + '&from-date=' + last_run_date + '&sort=-created_at&sort=%2Bstatus&field=scan-ids&branch=' + branch;
            var resp = this._makeRestApiCall(apibaseurl, configId, token, query, "get");
            var jsonLastScanSummResp = JSON.parse(resp.getBody());
        } catch (err) {
            gs.error(this.MSG + " :getScanListFilterByBranch :Error in getting the scan details with branch filter: " + err);
            return -1;
        }

        return jsonLastScanSummResp;

    },

    //List of scanIds for a given app/project filter by branch name
    getScanListFilterByMultipleBranch: function(configId, projectId, last_run_date, branches) {
        try {
            var request = new sn_ws.RESTMessageV2();
            var branch = '';
            var config = this._getConfig(configId);
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var method = "post";
            var token = this.getAccessToken(accesscontrolbaseUrl, config, method, request, configId);
            for (var item in branches) {
                branch += '&branches=' + encodeURIComponent(branches[item]);
            }

            var query = '/api/scans/?statuses=Completed&project-id=' + projectId + '&from-date=' + last_run_date + '&sort=-created_at&sort=%2Bstatus&field=scan-ids' + branch;

            var resp = this._makeRestApiCall(apibaseurl, configId, token, query, "get");
            var jsonLastScanSummResp = JSON.parse(resp.getBody());
        } catch (err) {
            gs.error(this.MSG + " :getScanListFilterByMultipleBranch :Error in getting the scan details with branch filter: " + err);
            return -1;
        }

        return jsonLastScanSummResp;
    },


    //Second Last scanId for a given app/project
    getSecondLastScan: function(configId, projectId, scanId, primaryBranch) {
        try {
            var request = new sn_ws.RESTMessageV2();
            var config = this._getConfig(configId);
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var method = "post";
            var token = this.getAccessToken(accesscontrolbaseUrl, config, method, request, configId);
            var isPrimaryBranchEnabled = config.sync_only_primary_branch.toString();
            var query = '';
            if (isPrimaryBranchEnabled == 'true' && null != primaryBranch && '' != primaryBranch)
                query = '/api/scans/?offset=0&limit=1000&statuses=Completed&project-id=' + projectId + '&sort=-created_at&sort=%2Bstatus&field=scan-ids&branch=' + primaryBranch;
            else
                query = '/api/scans/?offset=0&limit=1000&statuses=Completed&project-id=' + projectId + '&sort=-created_at&sort=%2Bstatus&field=scan-ids';
            var resp = this._makeRestApiCall(apibaseurl, configId, token, query, "get");
            var body = resp.getBody();
            var secondscan = -1;
            var ScanJson = JSON.parse(body);
            for (var i = 0; i <= ScanJson.scans.length; i++) {
                if (ScanJson.scans[i] != undefined) {
                    if (ScanJson.scans[i].id == scanId && ScanJson.scans[i + 1] != undefined) {
                        secondscan = ScanJson.scans[i + 1].id;
                    }
                }
            }
        } catch (err) {
            gs.error(this.MSG + " :getSecondLastScan :Error in getting the second last scan ID: " + err);
            throw err;
        }
        return secondscan;
    },

    // last  scan details of a given appId 
    getScanInfo: function(configId, appId, offset, last_run_date) {
        try {
            var request = new sn_ws.RESTMessageV2();
            var config = this._getConfig(configId);
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var limit_val = config.limit;
            var method = "post";
            var token = this.getAccessToken(accesscontrolbaseUrl, config, method, request, configId);
            var query = '/api/scans/?offset=0&limit=1&statuses=Completed&project-id=' + appId + '&from-date=' + last_run_date + '&sort=-created_at&sort=%2Bstatus&field=scan-ids';
            var resp = this._makeRestApiCall(apibaseurl, configId, token, query, "get");
            var jsonLastScanSummResp = JSON.parse(resp.getBody());
        } catch (err) {
            gs.error(this.MSG + " getScanInfo: Error while getting the scan info: " + err);
            throw err;
        }
        return jsonLastScanSummResp;

    },

    // last  scan  config details of a given appId  and scanId
    getScanConfigInfo: function(configId, appId, scanId) {
        var responseBody = '';
        try {
            var request = new sn_ws.RESTMessageV2();
            var config = this._getConfig(configId);
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var method = "post";
            var token = this.getAccessToken(accesscontrolbaseUrl, config, method, request, configId);
            var query = '/api/configuration/scan?project-id=' + appId + '&scan-id=' + scanId;
            var response = this._makeRestApiCall(apibaseurl, configId, token, query, "get");
            responseBody = JSON.parse(response.getBody());
        } catch (err) {
            gs.error(this.MSG + " getScanConfigInfo: Error while getting the scan configuration info: " + err);
            throw err;
        }
        return responseBody;

    },

    //List of Last scanId for a given app/project
    getLastScan: function(configId, projectId) {
        try {
            var request = new sn_ws.RESTMessageV2();
            var config = this._getConfig(configId);
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var method = "post";
            var token = this.getAccessToken(accesscontrolbaseUrl, config, method, request, configId);
            var query = '/api/scans/?offset=0&amp;limit=1&amp;statuses=Completed&amp;project-id=' + projectId + '&amp;sort=-created_at&amp;sort=%2Bstatus&amp;field=scan-ids';

        } catch (err) {
            gs.error(this.MSG + " :getLastScan :Error in getting last scan details." + err);
            throw err;
        }
        return this._makeRestApiCall(apibaseurl, configId, token, query, "get");
    },

    // last  scan details of a given scanId 
    getLastScanInfo: function(configId, appId, scanId) {
        try {
            var request = new sn_ws.RESTMessageV2();
            var config = this._getConfig(configId);
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var method = "post";
            var token = this.getAccessToken(accesscontrolbaseUrl, config, method, request, configId);
            var query = '/api/scans/' + scanId;
        } catch (err) {
            gs.error(this.MSG + " getScanInfo: Error while getting the last scan info: " + err);
            throw err;
        }
        return this._makeRestApiCall(apibaseurl, configId, token, query, "get");

    },


    //scan details of a given scanId
    getQueryInfo: function(configId, scanId) {
        var queryJSON;
        try {
            var request = new sn_ws.RESTMessageV2();
            var config = this._getConfig(configId);
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var method = "post";
            var token = this.getAccessToken(accesscontrolbaseUrl, config, method, request, configId);
            var query = '/api/results/?scan-id=' + scanId + '&offset=0&limit=10000&sort=%2Bstatus&sort=%2Bseverity';
            var resp = this._makeRestApiCall(apibaseurl, configId, token, query, "get");
            var body = resp.getBody();
            queryJSON = JSON.parse(body);
        } catch (err) {
            gs.error(this.MSG + " getQueryInfo: Error while getting the Query Info: " + err);
            throw err;
        }
        return queryJSON;

    },

    processQueryData: function(configId, scanId) {
        var queryJSON = this.getQueryInfo(configId, scanId);
        var query = [];
        var index = 0;
        for (item in queryJSON.results) {
            var singleQuery = queryJSON.results[item];
            if (singleQuery.type == 'sast' || singleQuery.type == 'kics') {
                var queryIndex = this.checkQueryIndex(query, singleQuery.data.queryName);
                if (queryIndex != -1)
                    query[queryIndex].count = query[queryIndex].count + 1;
                else {
                    var updatedQuery = {};
                    updatedQuery.category_name = singleQuery.data.queryName;
                    updatedQuery.severity = singleQuery.severity;
                    updatedQuery.count = 1;
                    query[index] = updatedQuery;
                    index++;
                }
            }
        }
        return query;
    },

    checkQueryIndex: function(query, name) {
        for (queryIndex in query)
            if (query[queryIndex].category_name === name)
                return queryIndex;
        return -1;
    },

    // to fetch scan details of particular scanId
    getScanDetails: function(configId, scanId) {
        try {
            var request = new sn_ws.RESTMessageV2();
            var config = this._getConfig(configId);
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var method = "post";
            var token = this.getAccessToken(accesscontrolbaseUrl, config, method, request, configId);
            var query = '/api/scans/?offset=0&limit=2000&scan-ids=' + scanId + '&sort=-created_at&sort=%2Bstatus&field=scan-ids';
        } catch (err) {
            gs.error(this.MSG + " getScanDetails: Error while getting the scan details: " + err);
            throw err;
        }
        return this._makeRestApiCall(apibaseurl, configId, token, query, "get");

    },

    //to get total vul item 
    getTotalVulcount: function(configId, scanId) {
        try {
            var request = new sn_ws.RESTMessageV2();
            var config = this._getConfig(configId);
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var ui_severity = config.severity;
            var severityFilter = false;
            if (null != ui_severity && '' != ui_severity) {
                severityFilter = true;
                var severity = config.severity;
            }
            var method = "post";
            var token = this.getAccessToken(accesscontrolbaseUrl, config, method, request, configId);

            var query = '/api/results/?scan-id=' + scanId + '&severity=' + severity + '&offset=0&limit=1';
            var resp = this._makeRestApiCall(apibaseurl, configId, token, query, "get");
            var body = resp.getBody();
            var jsonLastScanReportResp = JSON.parse(body);
            var count = jsonLastScanReportResp.totalCount;
        } catch (err) {
            gs.error(this.MSG + " getTotalVulcount: Error while getting the total vul count for scanId: " + scanId + " with error: " + err);
            return -1;
        }

        return count;

    },

    //to get Api Security vulnerability count
    getApiSecVulCount: function(configId, scanId) {
        try {
            var request = new sn_ws.RESTMessageV2();
            var config = this._getConfig(configId);
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var ui_severity = config.severity;
            var method = "get";
            var count = 0;
            var token = this.getAccessToken(accesscontrolbaseUrl, config, method, request, configId);
            var query = '/api/apisec/static/api/risks/' + scanId + '/group/severity';
            var resp = this._makeRestApiCall(apibaseurl, configId, token, query, "get");
            var body = resp.getBody();
            var apiSecJson = JSON.parse(body);

            if (null != ui_severity && '' != ui_severity) {
                var severity_array = this.getSeverityFromUI(configId);
            }

            for (var item in apiSecJson.groups) {
                var severity = apiSecJson.groups[item].top_level_group_value.toUpperCase();
                if (severity_array.indexOf(severity) != -1) {
                    count += apiSecJson.groups[item].total_records;
                }
            }
        } catch (err) {
            gs.error(this.MSG + " getApiSecVulCount: Error while getting the apisec vul count for scanId: " + scanId + " with error: " + err);
            return -1;
        }

        return count;

    },

    //to get SAST  vul item 
    getSASTVulcount: function(configId, scanId) {
        try {
            var request = new sn_ws.RESTMessageV2();
            var config = this._getConfig(configId);
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var method = "post";
            var token = this.getAccessToken(accesscontrolbaseUrl, config, method, request, configId);

            var query = '/api/scan-summary/?scan-ids=' + scanId + '&include-severity-status=true&include-status-counters=true&include-queries=true&include-files=true&apply-predicates=false';
            var resp = this._makeRestApiCall(apibaseurl, configId, token, query, "get");
            var body = resp.getBody();
            var ScanSummaryJson = JSON.parse(body);

            for (var item in ScanSummaryJson.scansSummaries) {
                var count = ScanSummaryJson.scansSummaries[item].sastCounters.totalCounter;
            }
        } catch (err) {
            gs.error(this.MSG + " getSASTVulcount: Error while getting the SAST vul count for scanId: " + scanId + " with error: " + err);
            return -1;
        }

        return count;

    },

    //to get total SAST and KICS  vul item 
    getTotal_SAST_KICS_Vulcount: function(configId, scanId) {
        try {
            var request = new sn_ws.RESTMessageV2();
            var config = this._getConfig(configId);
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var method = "post";
            var token = this.getAccessToken(accesscontrolbaseUrl, config, method, request, configId);
            var flaws = 0;
            var query = '/api/scan-summary/?scan-ids=' + scanId + '&include-severity-status=true&include-status-counters=true&include-queries=true&include-files=true&apply-predicates=false';
            var resp = this._makeRestApiCall(apibaseurl, configId, token, query, "get");
            var body = resp.getBody();
            var ScanSummaryJson = JSON.parse(body);

            for (var item in ScanSummaryJson.scansSummaries) {
                var counts = ScanSummaryJson.scansSummaries[item].sastCounters.totalCounter + ScanSummaryJson.scansSummaries[item].kicsCounters.totalCounter;
                flaws += counts;
            }
        } catch (err) {
            gs.error(this.MSG + " getTotal_SAST_KICS_Vulcount: Error while getting the total sast and kics vul count" + err + scanId);
            return 0;
        }

        return flaws;

    },

    // to get vulnerabilities information of scanId
    getVulInfo: function(configId, scanId, offsetId, severity) {
        try {
            var request = new sn_ws.RESTMessageV2();
            var config = this._getConfig(configId);
            var includesca = this.importScaFlaw(configId);
            var includesast = this.importSastFlaw(configId);
            var includekics = this.importKicsFlaw(configId);

            var limit_val = config.limit;
            var query = '/api/results/?scan-id=' + scanId + '&offset=' + offsetId + '&limit=' + limit_val + '&severity=' + severity + '&sort=-severity';
            var exclude_dev_and_test_dependencies = config.exclude_dev_and_test_dependencies;
            if (exclude_dev_and_test_dependencies) {
                query += '&exclude-result-types=DEV_AND_TEST';
            }

            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var method = "post";
            var token = this.getAccessToken(accesscontrolbaseUrl, config, method, request, configId);

        } catch (err) {
            gs.error(this.MSG + " getVulInfo: Error while getting the vul Info: " + err);
            return -1;
        }
        return this._makeRestApiCall(apibaseurl, configId, token, query, "get");

    },

    // to get API Security vulnerabilities information of scanId
    getApiSecVulInfo: function(configId, scanId, offsetId) {
        try {
            var request = new sn_ws.RESTMessageV2();
            var config = this._getConfig(configId);
            var per_page = config.limit;

            var query = '/api/apisec/static/api/risks/' + scanId + '?page=' + offsetId + '&per_page=' + per_page;
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var method = "get";
            var token = this.getAccessToken(accesscontrolbaseUrl, config, method, request, configId);

        } catch (err) {
            gs.error(this.MSG + " getApiSecVulInfo: Error while getting the apisec vul Info: " + err);
            return -1;
        }
        return this._makeRestApiCall(apibaseurl, configId, token, query, "get");

    },

    //Sca scan details of a given scanId
    getScanSummaryInfo: function(configId, scanId) {
        try {
            var request = new sn_ws.RESTMessageV2();
            var config = this._getConfig(configId);
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var method = "post";
            var token = this.getAccessToken(accesscontrolbaseUrl, config, method, request, configId);

            var query = '/api/scan-summary/?scan-ids=' + scanId + '&include-severity-status=true&include-status-counters=true&include-queries=true&include-files=true&apply-predicates=false';
            var resp = this._makeRestApiCall(apibaseurl, configId, token, query, "get");
            var body = resp.getBody();
            var ScanSummaryJson = JSON.parse(body);
            var flaws = 0;
            var ui_severity = config.severity;
            var severityFilter = false;
            if (null != ui_severity && '' != ui_severity) {
                severityFilter = true;
                var severity_array = this.getSeverityFromUI(configId);
            }
            for (var item in ScanSummaryJson.scansSummaries) {
                for (var value in ScanSummaryJson.scansSummaries[item].scaCounters.severityCounters) {
                    var severity = ScanSummaryJson.scansSummaries[item].scaCounters.severityCounters[value].severity;
                    if (severity_array.indexOf(severity) != -1) {
                        var counts = ScanSummaryJson.scansSummaries[item].scaCounters.severityCounters[value].counter;
                        flaws += counts;
                    }
                }
                for (value in ScanSummaryJson.scansSummaries[item].scaContainersCounters.severityVulnerabilitiesCounters) {
                    var sca_container_severity = ScanSummaryJson.scansSummaries[item].scaContainersCounters.severityVulnerabilitiesCounters[value].severity;
                    if (severity_array.indexOf(sca_container_severity) != -1) {
                        var sca_container_counts = ScanSummaryJson.scansSummaries[item].scaContainersCounters.severityVulnerabilitiesCounters[value].counter;
                        flaws += sca_container_counts;
                    }
                }
            }

        } catch (err) {
            gs.error(this.MSG + " getScanSummaryInfo: Error while getting the scan summary Ids for scanId: " + scanId + "with error: " + err);
            return -1;

        }
        return flaws;

    },

    //Sast scan details of a given scanId
    getSastScanSummaryInfo: function(configId, scanId) {
        try {
            var request = new sn_ws.RESTMessageV2();
            var config = this._getConfig(configId);
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var method = "post";
            var token = this.getAccessToken(accesscontrolbaseUrl, config, method, request, configId);

            var query = '/api/scan-summary/?scan-ids=' + scanId + '&include-severity-status=true&include-status-counters=true&include-queries=true&include-files=true&apply-predicates=false';
            var resp = this._makeRestApiCall(apibaseurl, configId, token, query, "get");
            var body = resp.getBody();
            var ScanSummaryJson = JSON.parse(body);
            var flaws = 0;
            var ui_severity = config.severity;
            var severityFilter = false;
            if (null != ui_severity && '' != ui_severity) {
                severityFilter = true;
                var severity_array = this.getSeverityFromUI(configId);
            }
            for (var item in ScanSummaryJson.scansSummaries) {
                for (var value in ScanSummaryJson.scansSummaries[item].sastCounters.severityCounters) {
                    var severity = ScanSummaryJson.scansSummaries[item].sastCounters.severityCounters[value].severity;
                    if (severity_array.indexOf(severity) != -1) {
                        var counts = ScanSummaryJson.scansSummaries[item].sastCounters.severityCounters[value].counter;
                        flaws += counts;
                    }
                }
            }
        } catch (err) {
            gs.error(this.MSG + " getSastScanSummaryInfo: Error while getting the sast scan summary Ids for scanId: " + scanId + "with error: " + err);
            return -1;
        }
        return flaws;

    },

    //Kics scan details of a given scanId
    getKicsScanSummaryInfo: function(configId, scanId) {
        try {
            var request = new sn_ws.RESTMessageV2();
            var config = this._getConfig(configId);
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var method = "post";
            var token = this.getAccessToken(accesscontrolbaseUrl, config, method, request, configId);

            var query = '/api/scan-summary/?scan-ids=' + scanId + '&include-severity-status=true&include-status-counters=true&include-queries=true&include-files=true&apply-predicates=false';
            var resp = this._makeRestApiCall(apibaseurl, configId, token, query, "get");
            var body = resp.getBody();
            var ScanSummaryJson = JSON.parse(body);
            var flaws = 0;
            var ui_severity = config.severity;
            var severityFilter = false;
            if (null != ui_severity && '' != ui_severity) {
                severityFilter = true;
                var severity_array = this.getSeverityFromUI(configId);
            }
            for (var item in ScanSummaryJson.scansSummaries) {
                for (var value in ScanSummaryJson.scansSummaries[item].kicsCounters.severityCounters) {
                    var severity = ScanSummaryJson.scansSummaries[item].kicsCounters.severityCounters[value].severity;

                    if (severity_array.indexOf(severity) != -1) {
                        var counts = ScanSummaryJson.scansSummaries[item].kicsCounters.severityCounters[value].counter;
                        flaws += counts;
                    }
                }
            }
        } catch (err) {
            gs.error(this.MSG + " getKicsScanSummaryInfo: Error while getting the kics scan summary Ids for scanId: " + scanId + "with error: " + err);
            return -1;

        }
        return flaws;

    },

    //Container Security scan details of a given scanId
    getContainerSecurityScanSummaryInfo: function(configId, scanId) {
        try {
            var request = new sn_ws.RESTMessageV2();
            var config = this._getConfig(configId);
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var method = "post";
            var token = this.getAccessToken(accesscontrolbaseUrl, config, method, request, configId);

            var query = '/api/scan-summary/?scan-ids=' + scanId + '&include-severity-status=true&include-status-counters=true&include-queries=true&include-files=true&apply-predicates=false';
            var resp = this._makeRestApiCall(apibaseurl, configId, token, query, "get");
            var body = resp.getBody();
            var ScanSummaryJson = JSON.parse(body);
            var flaws = 0;
            var ui_severity = config.severity;
            var severityFilter = false;
            if (null != ui_severity && '' != ui_severity) {
                severityFilter = true;
                var severity_array = this.getSeverityFromUI(configId);
            }
            for (var item in ScanSummaryJson.scansSummaries) {
                for (var value in ScanSummaryJson.scansSummaries[item].containersCounters.severityCounters) {
                    var severity = ScanSummaryJson.scansSummaries[item].containersCounters.severityCounters[value].severity;

                    if (severity_array.indexOf(severity) != -1) {
                        var counts = ScanSummaryJson.scansSummaries[item].containersCounters.severityCounters[value].counter;
                        flaws += counts;
                    }
                }
            }
        } catch (err) {
            gs.error(this.MSG + " getContainerScanSummaryInfo: Error while getting the kics scan summary Ids for scanId: " + scanId + "with error: " + err);
            return -1;

        }
        return flaws;

    },

    //API Security scan details of a given scanId
    getApiSecurityScanSummaryInfo: function(configId, scanId) {
        try {
            var request = new sn_ws.RESTMessageV2();
            var config = this._getConfig(configId);
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var method = "post";
            var token = this.getAccessToken(accesscontrolbaseUrl, config, method, request, configId);

            var query = '/api/scan-summary/?scan-ids=' + scanId + '&include-severity-status=true&include-status-counters=true&include-queries=true&include-files=true&apply-predicates=false';
            var resp = this._makeRestApiCall(apibaseurl, configId, token, query, "get");
            var body = resp.getBody();
            var ScanSummaryJson = JSON.parse(body);
            var flaws = 0;
            var ui_severity = config.severity;
            var severityFilter = false;
            if (null != ui_severity && '' != ui_severity) {
                severityFilter = true;
                var severity_array = this.getSeverityFromUI(configId);
            }

            for (var item in ScanSummaryJson.scansSummaries) {
                var scanSummary = ScanSummaryJson.scansSummaries[item];
                if (scanSummary.apiSecCounters && scanSummary.apiSecCounters.apiSecTotal !== undefined) {
                    flaws += scanSummary.apiSecCounters.apiSecTotal;
                }
            }
        } catch (err) {
            gs.error(this.MSG + " getApiSecurityScanSummaryInfo: Error while getting the api security scan summary Ids for scanId: " + scanId + "with error: " + err);
            return -1;
        }
        return flaws;

    },
    //ScoreCard scan details of a given scanId
    getScoreCardScanSummaryInfo: function(configId, scanId) {
        try {
            var request = new sn_ws.RESTMessageV2();
            var config = this._getConfig(configId);
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var method = "post";
            var counts = 0;
            var token = this.getAccessToken(accesscontrolbaseUrl, config, method, request, configId);

            var query = '/api/micro-engines/scans/' + scanId + '/scan-overview';
            var resp = this._makeRestApiCall(apibaseurl, configId, token, query, "get");
            var body = resp.getBody();
            var ScanSummaryJson = JSON.parse(body);
            var flaws = 0;
            var ui_severity = config.severity;
            var severityFilter = false;
            if (null != ui_severity && '' != ui_severity) {
                severityFilter = true;
                var severity_array = this.getSeverityFromUI(configId);
            }
            for (var item in ScanSummaryJson.engineOverviews) {
                if (ScanSummaryJson.engineOverviews[item].name == 'Scorecard' && ScanSummaryJson.engineOverviews[item].totalRisks != 0) {

                    if (severity_array.indexOf('CRITICAL') != -1) {
                        counts = ScanSummaryJson.engineOverviews[item].riskSummary.critical;
                        flaws += counts;
                    }
                    if (severity_array.indexOf('HIGH') != -1) {
                        counts = ScanSummaryJson.engineOverviews[item].riskSummary.high;
                        flaws += counts;
                    }
                    if (severity_array.indexOf('MEDIUM') != -1) {
                        counts = ScanSummaryJson.engineOverviews[item].riskSummary.medium;
                        flaws += counts;
                    }
                    if (severity_array.indexOf('LOW') != -1) {
                        counts = ScanSummaryJson.engineOverviews[item].riskSummary.low;
                        flaws += counts;
                    }
                    if (severity_array.indexOf('INFO') != -1) {
                        counts = ScanSummaryJson.engineOverviews[item].riskSummary.info;
                        flaws += counts;
                    }
                }
                if (ScanSummaryJson.engineOverviews[item].status != 'Completed') {
                    flaws = -1;
                }

            }
        } catch (err) {
            gs.error(this.MSG + " getContainerScanSummaryInfo: Error while getting the kics scan summary Ids for scanId: " + scanId + "with error: " + err);
            return -1;

        }
        return flaws;

    },

    //SecretDetection scan details of a given scanId
    getSecretDetectionScanSummaryInfo: function(configId, scanId) {
        try {
            var request = new sn_ws.RESTMessageV2();
            var config = this._getConfig(configId);
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var method = "post";
            var counts = 0;
            var token = this.getAccessToken(accesscontrolbaseUrl, config, method, request, configId);

            var query = '/api/micro-engines/scans/' + scanId + '/scan-overview';
            var resp = this._makeRestApiCall(apibaseurl, configId, token, query, "get");
            var body = resp.getBody();
            var ScanSummaryJson = JSON.parse(body);
            var flaws = 0;
            var ui_severity = config.severity;
            var severityFilter = false;
            if (null != ui_severity && '' != ui_severity) {
                severityFilter = true;
                var severity_array = this.getSeverityFromUI(configId);
            }
            for (var item in ScanSummaryJson.engineOverviews) {
                if (ScanSummaryJson.engineOverviews[item].name == '2ms' && ScanSummaryJson.engineOverviews[item].totalRisks != 0) {

                    if (severity_array.indexOf('CRITICAL') != -1) {
                        counts = ScanSummaryJson.engineOverviews[item].riskSummary.critical;
                        flaws += counts;
                    }
                    if (severity_array.indexOf('HIGH') != -1) {
                        counts = ScanSummaryJson.engineOverviews[item].riskSummary.high;
                        flaws += counts;
                    }
                    if (severity_array.indexOf('MEDIUM') != -1) {
                        counts = ScanSummaryJson.engineOverviews[item].riskSummary.medium;
                        flaws += counts;
                    }
                    if (severity_array.indexOf('LOW') != -1) {
                        counts = ScanSummaryJson.engineOverviews[item].riskSummary.low;
                        flaws += counts;
                    }
                    if (severity_array.indexOf('INFO') != -1) {
                        counts = ScanSummaryJson.engineOverviews[item].riskSummary.info;
                        flaws += counts;
                    }
                }
                if (ScanSummaryJson.engineOverviews[item].status != 'Completed') {
                    flaws = -1;
                }

            }
        } catch (err) {
            gs.error(this.MSG + " getContainerScanSummaryInfo: Error while getting the kics scan summary Ids for scanId: " + scanId + "with error: " + err);
            return -1;

        }
        return flaws;

    },

    getSCADeltaVul: function(configId, appId, scanId, secondlastscan) {
        try {
            var request = new sn_ws.RESTMessageV2();
            var config = this._getConfig(configId);
            var accesscontrolbaseUrl = config.checkmarxone_server_url;
            var apibaseurl = config.checkmarxone_api_base_url;
            var method = "post";
            var limit_val = config.limit;
            var token = this.getAccessToken(accesscontrolbaseUrl, config, method, request, configId);
            var query = '/api/sca/scan-results/scans/' + scanId + '/compare-risks?previousScanId=' + secondlastscan;
            var resp = this._makeRestApiCall(apibaseurl, configId, token, query, "get");
        } catch (err) {
            gs.error(this.MSG + " getSCADeltaVul: Error while getting the SCA delta state for scanId: " + scanId + "with error: " + err);
            return -1;
        }
        return resp;

    },

    //To get remediation status for state mapping
    getSASTRemediationStatus: function(status, state) {
        try {

            if (state == 'TO_VERIFY' || status == 'FIXED' || status == 'RESOLVED') {
                var remediation_status = status;
            } else {
                remediation_status = state;
            }
        } catch (err) {
            gs.error(this.MSG + " getRemediationStatus: Error while getting the sast remediation status." + err);

        }
        return remediation_status;

    },

    //To get remediation status for state mapping
    getSCARemediationStatus: function(status, state) {
        try {

            if (state == 'NOT_IGNORED' || status == 'FIXED' || status == 'RESOLVED' || state == 'TO_VERIFY') {
                var remediation_status = status;
            } else {
                remediation_status = state;
            }
        } catch (err) {
            gs.error(this.MSG + " getSCARemediationStatus: Error while getting the SCA remediation status." + err);

        }
        return remediation_status;

    },

    //To get remediation status for state mapping
    getKICSRemediationStatus: function(status, state) {
        try {

            if (state == 'NOT_IGNORED' || status == 'FIXED' || status == 'RESOLVED' || state == 'TO_VERIFY') {
                var remediation_status = status;
            } else {
                remediation_status = state;
            }
        } catch (err) {
            gs.error(this.MSG + " getKICSRemediationStatus: Error while getting the kics remediation status." + err);

        }
        return remediation_status;

    },

    getFirstDetectionDate: function() {
        try {
            var configId = '1234';
            var config = this._getConfig(configId);
            var include_first_found = config.include_first_detection_date;
        } catch (err) {
            gs.error(this.MSG + " getFirstDetectionDate: Error while getting the status of getFirstDetectionDate." + err);

        }
        return include_first_found;
    },

    //Devops Integration
    getProjectByLegacyId: function(configId, params) {
        return this._makeRestCallJSON(configId, 'Project list', JSON.parse(params));
    },

    _getConfig: function(configId) {
        try {
            if (configId && configId != '1234') {
                return new sn_sec_int.Implementation().getConfiguration(configId);
            } else {
                var gr = new GlideRecord("x_chec3_chexone_checkmarxone_configuration");
                gr.query();
                gr.next();
                var newconfig = {
                    "client_secret": gr.client_secret.getDecryptedValue(),
                    "client_id": gr.getValue("client_id"),
                    "tenant": gr.getValue("tenant"),
                    "checkmarxone_api_base_url": gr.getValue("checkmarxone_api_base_url"),
                    "checkmarxone_server_url": gr.getValue("checkmarxone_server_url"),
                    "limit": gr.getValue("limit"),
                    "log_level": gr.getValue("log_level"),
                    "include_first_detection_date": gr.getValue("include_first_detection_date") === "1",
                    "import_sca": gr.getValue("import_sca") === "1",
                    "import_sast": gr.getValue("import_sast") === "1",
                    "import_kics": gr.getValue("import_kics") === "1",
                    "include_container_security": gr.getValue("include_container_security") === "1",
                    "include_only_similarity_id": gr.getValue("include_only_similarity_id") === "1",
                    "include_api_security": gr.getValue("include_api_security") === "1",
                    "include_ossf_scorecard": gr.getValue("include_ossf_scorecard") === "1",
                    "include_secret_detection": gr.getValue("include_secret_detection") === "1",
                    "triaging_in_snow": gr.getValue("triaging_in_snow") === "1",
                    "access_token": gr.access_token.getDecryptedValue(),
                    "vulnerability_threshold_level": gr.getValue("vulnerability_threshold_level"),
                    "scan_synchronization": gr.getValue("scan_synchronization"),
                    "sync_only_primary_branch": gr.getValue("sync_only_primary_branch") === "1",
                    "list_projects": gr.getValue("list_of_project_id_s"),
                    "result_states": gr.getValue("result_states"),
                    "project_filter_by_name": gr.getValue("project_filter_by_name"),
                    "filter_project": gr.getValue("filter_project"),
                    "link": gr.getValue("link"),
                    "exclude_dev_and_test_dependencies": gr.getValue("exclude_dev_and_test_dependencies") === "1",
                    "scan_type": gr.getValue("scan_type"),
                    "severity": gr.getValue("severity"),
                    "close_findings_of_deleted_projects": gr.getValue("close_findings_of_deleted_projects") === "1",
                };
            }
        } catch (err) {
            gs.error(this.MSG + " :_getConfig :Error in getting the configuration." + err);
            throw err;
        }
        return newconfig;
    },

    getAccessToken: function(baseUrl, config, method, request, configId) {
        //to get access token from sn_sec_cmn_int_auth_config table
        var getConfig = this.SEC_UTIL.getConfig(configId);
        var auth_config = getConfig.auth_config;
        return this._getToken(baseUrl, config, method, request, config.client_id, config.client_secret, config.ast_client_id, config.tenant, auth_config, configId);
    },

    _getToken: function(baseUrl, config, method, request, username, password, ast_client_id, tenant, currentToken, configId) {
        try {
            var accessToken = currentToken;
            if (accessToken == null || accessToken == "" || this._isTokenExpired(this._getExpTimeFromAccessToken(accessToken)) || !this._checkClientId(username, accessToken)) {
                gs.info("Token is expired or client Id is changed, Recreating token..");
                var fullUrl = baseUrl + '/auth/realms/' + tenant + '/protocol/openid-connect/token';
                var query = "client_id=" + username + "&grant_type=" + "client_credentials" + "&client_secret=" + password;
                request.setEndpoint(fullUrl);
                request.setHttpMethod(method);
                var log_level = config.log_level;
                request.setLogLevel(log_level);
                request.setRequestBody(query);
                request.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
                request.setRequestHeader("Accept", "application/json");
                request.setRequestHeader('User-Agent', this.getUserAgentHeaderDetails());
                //Convert the object to string and set it to Request Body-
                request.setRequestBody(query);
                var response = this._checkResponseStatus(request, configId, method, false);
                var responseBody = response.getBody();
                var tokenResponse = JSON.parse(responseBody);
                accessToken = tokenResponse.access_token;
                var tokenexpiretime = this._getTokenExpiredTime(this._getExpTimeFromAccessToken(accessToken));
                var obj = {
                    "expires_on": tokenexpiretime.toString(),
                    "auth_config": accessToken
                };
                //to set access token in sn_sec_cmn_int_auth_config table
                this.SEC_UTIL.setConfig(configId, obj);
            }

        } catch (err) {
            gs.error(this.MSG + " :_getToken : Error while getting the token." + err);
            throw err;
        }
        return accessToken;
    },

    getNewToken: function(baseUrl, config, method, request, username, password, tenant, saveinstanceflag, configId) {

        try {
            var fullUrl = baseUrl + '/auth/realms/' + tenant + '/protocol/openid-connect/token';
            var query = "client_id=" + username + "&grant_type=" + "client_credentials" + "&client_secret=" + password;
            request.setEndpoint(fullUrl);
            request.setHttpMethod(method);
            var log_level = config.log_level;
            request.setLogLevel(log_level);
            request.setRequestBody(query);
            request.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
            request.setRequestHeader("Accept", "application/json");
            request.setRequestHeader('User-Agent', this.getUserAgentHeaderDetails());
            //Convert the object to string and set it to Request Body-
            request.setRequestBody(query);
            var response = request.execute();
            var status = response.getStatusCode();
            var accessToken = '';
            if (status == 200 || status == 202) {
                var responseBody = response.getBody();
                var tokenResponse = JSON.parse(responseBody);
                accessToken = tokenResponse.access_token;
                if (saveinstanceflag == "true") {
                    var tokenexpiretime = this._getTokenExpiredTime(this._getExpTimeFromAccessToken(accessToken));
                    var obj = {
                        "expires_on": tokenexpiretime.toString(),
                        "auth_config": accessToken
                    };
                    //to set access token in sn_sec_cmn_int_auth_config table
                    this.SEC_UTIL.setConfig(configId, obj);
                }

            }

        } catch (err) {

            gs.error(this.MSG + " :getNewToken : Error while getting the new token." + err);
            throw err;

        }

        return accessToken;

    },

    getNewTokenForValidation: function(baseUrl, config, method, request, username, password, tenant, saveinstanceflag, configId) {
        try {
            var fullUrl = baseUrl + '/auth/realms/' + tenant + '/protocol/openid-connect/token';
            var query = "client_id=" + username + "&grant_type=" + "client_credentials" + "&client_secret=" + password;
            request.setEndpoint(fullUrl);
            request.setHttpMethod(method);
            var log_level = config.log_level;
            request.setLogLevel(log_level);
            request.setRequestBody(query);
            request.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
            request.setRequestHeader("Accept", "application/json");
            request.setRequestHeader('User-Agent', this.getUserAgentHeaderDetails());
            //Convert the object to string and set it to Request Body-
            request.setRequestBody(query);
            var response = request.execute();
            var status = response.getStatusCode();
            var accessToken = '';
            if (status == 200 || status == 202) {
                var responseBody = response.getBody();
                var tokenResponse = JSON.parse(responseBody);
                accessToken = tokenResponse.access_token;

                var tokenPayload = accessToken.split(".")[1];
                var tokenPayloadJson = JSON.parse(gs.base64Decode(tokenPayload));
                var permissionFlag = 'true';
                var missingPermissions = '';
                if (null != tokenPayloadJson["roles_ast"]) {
                    var permissions = tokenPayloadJson["roles_ast"];
                    var requiredPermissions = this.getRequiredPermission(configId);
                    for (var item in requiredPermissions) {
                        if (permissions.indexOf(requiredPermissions[item]) == -1) {
                            permissionFlag = 'false';
                            if (missingPermissions != '')
                                missingPermissions += ', ';
                            missingPermissions += requiredPermissions[item];
                        }
                    }
                } else {
                    permissionFlag = 'false';
                    missingPermissions = this.getRequiredPermission(configId).toString();
                }
                if (permissionFlag == 'false')
                    throw (new Error('Credential validation failed due to missing Permissions: ' + missingPermissions));


                if (saveinstanceflag == "true") {
                    var tokenexpiretime = this._getTokenExpiredTime(this._getExpTimeFromAccessToken(accessToken));
                    var obj = {
                        "expires_on": tokenexpiretime.toString(),
                        "auth_config": accessToken
                    };
                    //to set access token in sn_sec_cmn_int_auth_config table
                    this.SEC_UTIL.setConfig(configId, obj);
                }

            }

        } catch (err) {

            gs.error(this.MSG + " :getNewTokenForValidation : Error while getting the new token." + err);
            throw err;

        }

        return accessToken;

    },

    // get required permission from config
    getRequiredPermission: function(configId) {
        var config = this._getConfig(configId);
        var requiredPermission = [];
        var requiredPermissionarr;
        var required_permission = config.permission;
        if (required_permission && required_permission.length > 0) {
            requiredPermissionarr = required_permission.split(";");
            for (var id in requiredPermissionarr) {
                requiredPermission.push(requiredPermissionarr[id]);
            }
        }
        return requiredPermission;

    },

    getUserAgentHeaderDetails: function() {
        try {
            var plugin = new GlideRecord("sys_store_app");
            plugin.get("scope", "x_chec3_chexone");
            var pluginname_version = "plugin_name=" + plugin.getValue("name") + ";plugin_version=" + plugin.getValue("version");
            return pluginname_version.toString();
        } catch (err) {
            gs.error(this.MSG + " :_getUserAgentHeaderDetails : Error while getting the plugin name and version." + err);
            throw err;

        }
    },

    //Compare current clientId with accessToken's clientId
    _checkClientId: function(clientId, accessToken) {
        try {
            var tokenPayload = accessToken.split(".")[1];
            var tokenPayloadJson = JSON.parse(gs.base64Decode(tokenPayload));
            var clientIdToken = tokenPayloadJson.azp;
            if (clientId == clientIdToken)
                return true;
            return false;
        } catch (err) {
            gs.error(this.MSG + " :checkClientId :Error in checkClientId." + err);
            return false;
        }

    },
    // Get expiry token from JWT access token
    _getExpTimeFromAccessToken: function(accessToken) {
        try {
            var splittedStr = accessToken.split(".");
            var decodedToken = JSON.parse(gs.base64Decode(splittedStr[1]));
            var expTime = decodedToken.exp;
        } catch (err) {
            gs.error(this.MSG + " :getExpTimeFromAccessToken :Error in getExpTimeFromAccessToken.");
            return 0;
        }
        return expTime;
    },
    // This method checks  if access token is expired or not.
    _isTokenExpired: function(tokenExpTime) {
        try {
            if (tokenExpTime == 0)
                return true;
            var dateTime = new GlideDateTime();
            var currentTime = dateTime.getNumericValue() / 1000;
            currentTime = parseInt(currentTime);
            if (currentTime > tokenExpTime)
                return true;
            else
                return false;
        } catch (err) {
            gs.error(this.MSG + " :isTokenExpired :Error in isTokenExpired()." + err);
            throw err;
        }
    },
    // This method is to return token expiry time.
    _getTokenExpiredTime: function(tokenExpTime) {
        try {
            var token_time = tokenExpTime * 1000;
            var dateTime = new GlideDateTime();
            dateTime.setNumericValue(parseInt(token_time));
            return dateTime.getDisplayValue();
        } catch (err) {
            gs.error(this.MSG + " :_getTokenExpiredTime :Error in _getTokenExpiredTime()." + err);
            throw err;
        }
    },

    _makeRestCall: function(apiurl, configId, token, apiPath, method, params) {
        var request;
        try {
            request = this.setRequestParams(apiurl, configId, token, apiPath, method, params);
        } catch (err) {
            gs.error(this.MSG + " :_makeRestCall :Error in making the REST call");
            throw err;
        }
        var response = request.execute();
        return response;
    },

    setRequestParams: function(baseUrl, configId, token, apiPath, method, params) {
        try {
            var fullUrl = baseUrl + apiPath;
            var r = new sn_ws.RESTMessageV2();
            r.setEndpoint(fullUrl);
            r.setHttpMethod(method);

            if (params) {
                fullUrl += '/?';
                Object.keys(params).forEach(function(key) {
                    r.setQueryParameter(key, params[key]);
                    fullUrl += key + '=' + gs.urlEncode(params[key]) + '&';
                });
                fullUrl = fullUrl.slice(0, fullUrl.length - 1);
            }
            var newHeader = "Bearer " + token;
            r.setRequestHeader('Authorization', newHeader);
            r.setRequestHeader('User-Agent', this.getUserAgentHeaderDetails());
            r.setHttpTimeout(30000);
            var config = this._getConfig(configId);
            var log_level = config.log_level;
            r.setLogLevel(log_level);
        } catch (err) {
            gs.error(this.MSG + " :setRequestParams :Error in setting the reqest params for REST API call");
            throw err;
        }
        return r;
    },

    setnewRequestParams: function(fullUrl, method, newtoken, configId, params) {
        try {
            var r = new sn_ws.RESTMessageV2();
            r.setEndpoint(fullUrl);
            r.setHttpMethod(method);

            if (params) {
                fullUrl += '/?';
                Object.keys(params).forEach(function(key) {
                    r.setQueryParameter(key, params[key]);
                    fullUrl += key + '=' + gs.urlEncode(params[key]) + '&';
                });
                fullUrl = fullUrl.slice(0, fullUrl.length - 1);
            }
            var newHeader = "Bearer " + newtoken;
            r.setRequestHeader('Authorization', newHeader);
            r.setRequestHeader('User-Agent', this.getUserAgentHeaderDetails());
            r.setHttpTimeout(30000);
            var config = this._getConfig(configId);
            var log_level = config.log_level;
            r.setLogLevel(log_level);
        } catch (err) {
            gs.error(this.MSG + " :setnewRequestParams :Error in setting the reqest params for REST API call");
            throw err;
        }
        return r;
    },

    _checkResponseStatus: function(request, configId, method, params) {
        try {
            var endpoint = request.getEndpoint();
            var response = request.execute();
            var status = response.getStatusCode();
            if (status == 200 || status == 202)
                return response;

            if (status <= 0)
                throw gs.getMessage("Request could not be completed: {0} Reason : {1}", [endpoint, response.getErrorMessage()]);
            if (status == 400) {
                throw gs.getMessage("Bad request: {0} Reason : {1}", [endpoint, response.getErrorMessage()]);
            }
            if (status == -1 || status == 408 || status == 504 || status == 502 || status == 500) {
                this.customSleep(5000);
                var nextResponse = request.execute();
                var nextStatus = nextResponse.getStatusCode();
                if (newStatus == 200 || nextStatus == 202) {
                    return nextResponse;
                } else {
                    throw gs.getMessage("Request timed out: {0} Reason : {1}", [endpoint, response.getErrorMessage()]);
                }
            }

            if (status == 401) {
                var tokenRequest = new sn_ws.RESTMessageV2();
                var config = this._getConfig(configId);
                var accesscontrolbaseUrl = config.checkmarxone_server_url;
                var apibaseurl = config.checkmarxone_api_base_url;
                var token_method = "post";
                var save_token_flag = "true";
                var token = this.getNewTokenForValidation(accesscontrolbaseUrl, config, token_method, tokenRequest, config.client_id, config.client_secret, config.tenant, save_token_flag, configId);
                var newRequest = this.setnewRequestParams(endpoint, method, token, configId, params);
                var newResponse = newRequest.execute();
                var newStatus = newResponse.getStatusCode();
                if (newStatus == 200 || newStatus == 202) {
                    return newResponse;
                } else {
                    throw gs.getMessage("Request not authorized: {0}", [endpoint, response.getErrorMessage()]);
                }
            }
            if (status == 403)
                throw gs.getMessage("Request forbidden: {0}", [endpoint, response.getErrorMessage()]);
            if (status == 404)
                throw gs.getMessage("Request not found: {0}", [endpoint, response.getErrorMessage()]);

            throw gs.getMessage('Checkmarx responded with error code {0} on: {1}', [status, endpoint]);
        } catch (err) {
            this.customSleep(5000);
            var catchResponse = request.execute();
            var catchStatus = catchResponse.getStatusCode();
            if (newStatus == 200 || nextStatus == 202) {
                return catchResponse;
            } else {
                gs.error(this.MSG + " :_checkResponseStatus :Error in checking the response of the API call." + err);
                throw err;
            }
        }
    },

    _makeConfigRestApiCall: function(baseUrl, configId, token, name, method) {
        try {
            var fullUrl = baseUrl + name;
            var r = new sn_ws.RESTMessageV2();
            r.setEndpoint(fullUrl);
            r.setHttpMethod(method);
            var newHeader = "Bearer " + token;
            r.setRequestHeader("Accept", "application/json");
            r.setRequestHeader("Authorization", newHeader);
            r.setRequestHeader('User-Agent', this.getUserAgentHeaderDetails());
            r.setHttpTimeout(30000);
            var config = this._getConfig(configId);
            var log_level = config.log_level;
            r.setLogLevel(log_level);
            var response = r.execute();
            var status = response.getStatusCode();
        } catch (err) {
            gs.error(this.MSG + " :_makeConfigRestApiCall :Error in making API call.");
            throw err;
        }
        return status;
    },

    _makeRestApiCall: function(baseUrl, configId, token, name, method, params) {
        try {
            var fullUrl = baseUrl + name;
            var r = new sn_ws.RESTMessageV2();
            r.setEndpoint(fullUrl);
            r.setHttpMethod(method);

            var newHeader = "Bearer " + token;
            r.setRequestHeader("Accept", "application/json");
            r.setRequestHeader("Authorization", newHeader);
            r.setRequestHeader('User-Agent', this.getUserAgentHeaderDetails());
            r.setHttpTimeout(30000);
            var config = this._getConfig(configId);
            var log_level = config.log_level;
            r.setLogLevel(log_level);
        } catch (err) {
            gs.error(this.MSG + " :_makeRestApiCall :Error in making API call.");
            throw err;
        }
        return this._checkResponseStatus(r, configId, method, params);
    },
    //For DevOps Integration
    _makeRestCallJSON: function(configId, token, name, params, pathParams, body) {
        var requestType = 'GET';
        var r = new sn_ws.RESTMessageV2('x_chec3_chexone.CheckmarxOneJson', name);
        var endpoint = this._getEndpointComponents(r.getEndpoint());
        if (pathParams) {
            Object.keys(pathParams).forEach(function(key) {
                r.setStringParameter(key, pathParams[key]);
                endpoint.path = endpoint.path.replace('${' + key + '}', pathParams[key]);
            });
        }

        if (params) {
            endpoint.path += '?';
            Object.keys(params).forEach(function(key) {
                r.setQueryParameter(key, gs.urlEncode(params[key]));
                endpoint.path += key + '=' + gs.urlEncode(params[key]) + '&';
            });
            endpoint.path = endpoint.path.slice(0, endpoint.path.length - 1);
        }
        if (!gs.nil(body) && body != {}) {
            requestType = 'POST';
            r.setRequestBody(JSON.stringify(body));
        }


        var newHeader = "Bearer " + token;
        r.setRequestHeader("Accept", "application/json");
        r.setRequestHeader("Authorization", newHeader);
        r.setRequestHeader('User-Agent', this.getUserAgentHeaderDetails());
        r.setHttpTimeout(30000);
        return this._checkResponseStatus(r, configId, requestType, params);
    },

    // Helper function to handle pagination for Project API calls potentially returning large datasets
    _makePaginatedApiCall: function(apiurl, configId, token, baseQuery, method, resultKey) {
        var MAX_LIMIT_WITHOUT_PAGINATION = 2000;
        var PAGINATION_CHUNK_SIZE = 1000; // Default chunk size for pagination
        var allResults = [];
        var totalCount = 0;
        var filteredTotalCount = 0;

        try {
            // Initial call to get the count
            var countQuery = baseQuery + (baseQuery.indexOf('?') === -1 ? '?' : '&') + 'offset=0&limit=1';
            var initialResponse = this._makeRestApiCall(apiurl, configId, token, countQuery, method);
            var initialBody = initialResponse.getBody();
            var initialJson = JSON.parse(initialBody);

            filteredTotalCount = initialJson.filteredTotalCount || 0;
            totalCount = initialJson.totalCount || 0; // Store totalCount if available

            // If no results, return empty structure
            if (filteredTotalCount === 0) {
                var emptyResult = {};
                emptyResult[resultKey] = [];
                emptyResult.totalCount = totalCount;
                emptyResult.filteredTotalCount = filteredTotalCount;
                return emptyResult;
            }

            // If count is manageable (< MAX_LIMIT_WITHOUT_PAGINATION), fetch all at once
            if (filteredTotalCount < MAX_LIMIT_WITHOUT_PAGINATION) {
                var fetchAllQuery = baseQuery + (baseQuery.indexOf('?') === -1 ? '?' : '&') + 'offset=0&limit=' + filteredTotalCount;
                var fetchAllResponse = this._makeRestApiCall(apiurl, configId, token, fetchAllQuery, method);
                var fetchAllBody = fetchAllResponse.getBody();
                // Return the parsed JSON directly
                return JSON.parse(fetchAllBody);
            }

            // If count is large, paginate
            var offset = 0;
            while (offset < filteredTotalCount) {
                var pageQuery = baseQuery + (baseQuery.indexOf('?') === -1 ? '?' : '&') + 'offset=' + offset + '&limit=' + PAGINATION_CHUNK_SIZE;
                var pageResponse = this._makeRestApiCall(apiurl, configId, token, pageQuery, method);
                var pageBody = pageResponse.getBody();
                var pageJson = JSON.parse(pageBody);

                if (pageJson && pageJson[resultKey] && pageJson[resultKey].length > 0) {
                    allResults = allResults.concat(pageJson[resultKey]);
                    offset += pageJson[resultKey].length; // More robust increment based on actual results returned
                    // Break if the API returns fewer results than the limit, indicating the end
                    if (pageJson[resultKey].length < PAGINATION_CHUNK_SIZE) {
                        break;
                    }
                } else {
                    gs.warn(this.MSG + ' Pagination query returned no results or unexpected format for key "' + resultKey + '". Stopping pagination.');
                    break; // Stop if no results are returned or format is wrong
                }
                // Safety break in case offset doesn't advance properly
                if (offset >= filteredTotalCount) {
                    break;
                }
            }

            // Construct the final aggregated result object
            var finalResult = {};
            finalResult[resultKey] = allResults;
            finalResult.totalCount = totalCount; // Use totalCount from initial call
            finalResult.filteredTotalCount = filteredTotalCount; // Use filteredTotalCount from initial call
            return finalResult;

        } catch (err) {
            if (pageQuery && pageQuery != undefined && pageQuery != 'undefined') {
                var query = pageQuery;
            } else if (fetchAllQuery && fetchAllQuery != undefined && fetchAllQuery != 'undefined') {
                query = fetchAllQuery;
            }
            gs.error(this.MSG + " _makePaginatedApiCall: Error during paginated API call for query starting with '" + query + "'. Error: " + err);
            // throw err;
        }
    },


    // Helper function to handle pagination for Scan API calls potentially returning large datasets
    _makePaginatedScansApiCall: function(apiurl, configId, token, baseQuery, method, resultKey) {
        var MAX_LIMIT_WITHOUT_PAGINATION = 1000;
        var PAGINATION_CHUNK_SIZE = 500; // Default chunk size for pagination
        var allResults = [];
        var totalCount = 0;
        var filteredTotalCount = 0;

        try {
            // Initial call to get the count
            var countQuery = baseQuery + (baseQuery.indexOf('?') === -1 ? '?' : '&') + 'offset=0&limit=1';
            var initialResponse = this._makeRestApiCall(apiurl, configId, token, countQuery, method);
            var initialBody = initialResponse.getBody();
            var initialJson = JSON.parse(initialBody);

            filteredTotalCount = initialJson.filteredTotalCount || 0;
            totalCount = initialJson.totalCount || 0; // Store totalCount if available

            // If no results, return empty structure
            if (filteredTotalCount === 0) {
                var emptyResult = {};
                emptyResult[resultKey] = [];
                emptyResult.totalCount = totalCount;
                emptyResult.filteredTotalCount = filteredTotalCount;
                return emptyResult;
            }

            // If count is manageable (< MAX_LIMIT_WITHOUT_PAGINATION), fetch all at once
            if (filteredTotalCount < MAX_LIMIT_WITHOUT_PAGINATION) {
                var fetchAllQuery = baseQuery + (baseQuery.indexOf('?') === -1 ? '?' : '&') + 'offset=0&limit=' + filteredTotalCount;
                var fetchAllResponse = this._makeRestApiCall(apiurl, configId, token, fetchAllQuery, method);
                var fetchAllBody = fetchAllResponse.getBody();
                // Return the parsed JSON directly
                return JSON.parse(fetchAllBody);
            }

            // If count is large, paginate and sleep after 5th iteration
            var offset = 0;
            while (offset < filteredTotalCount) {
                var pageQuery = baseQuery + (baseQuery.indexOf('?') === -1 ? '?' : '&') + 'offset=' + offset + '&limit=' + PAGINATION_CHUNK_SIZE;
                var pageResponse = this._makeRestApiCall(apiurl, configId, token, pageQuery, method);
                var pageBody = pageResponse.getBody();
                var pageJson = JSON.parse(pageBody);
                if (pageJson && pageJson[resultKey] && pageJson[resultKey].length > 0) {
                    allResults = allResults.concat(pageJson[resultKey]);
                    offset += pageJson[resultKey].length; // More robust increment based on actual results returned
                    // Break if the API returns fewer results than the limit, indicating the end
                    if (pageJson[resultKey].length < PAGINATION_CHUNK_SIZE) {
                        break;
                    }
                } else {
                    gs.warn(this.MSG + ' Pagination query returned no results or unexpected format for key "' + resultKey + '". Stopping pagination.');
                    break; // Stop if no results are returned or format is wrong
                }
                // Safety break in case offset doesn't advance properly
                if (offset >= filteredTotalCount) {
                    break;
                }
                this.customSleep(300);

            }

            // Construct the final aggregated result object
            var finalResult = {};
            finalResult[resultKey] = allResults;
            finalResult.totalCount = totalCount; // Use totalCount from initial call
            finalResult.filteredTotalCount = filteredTotalCount; // Use filteredTotalCount from initial call
            return finalResult;

        } catch (err) {
            if (pageQuery && pageQuery != undefined && pageQuery != 'undefined') {
                var query = pageQuery;
            } else if (fetchAllQuery && fetchAllQuery != undefined && fetchAllQuery != 'undefined') {
                query = fetchAllQuery;
            }

            gs.error(this.MSG + " _makePaginatedScansApiCall: Error during paginated API call for query starting with '" + query + "'. Error: " + err);
            // throw err;
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

    // 2022-12-08T09:33:00.028555Z to 2022-12-08 09:33:00
    parseDate: function(str) {
        var a = str.replace('T', ' ');
        var b = a.replace('T', ' ');
        var c = b.split('.')[0];
        var date = new GlideDateTime(c);
        return date;
    },

    //2022-12-08 09:33:00 to 2022-12-08,09:33:00
    parseDateWithComma: function(str) {
        var a = str.replace(/ /g, ',');
        return a;
    },

    //2022-12-08 09:33:00 to 2022-12-08T09:33:00.028555Z
    parseTZDate: function(str) {
        str1 = str.slice(0, str.length - 9) + 'T';
        str2 = str.slice(-8) + '.028555Z';
        if (str == "" || str == null) {
            str3 = str;
        } else {
            str3 = str1 + str2;
        }
        return str3;

    },

	// Helper function to escape CDATA content
    escapeCDATA: function(str) {
        if (str === null || typeof str === 'undefined' || str == '') {
			return '';
		}
        // When ]]> appears in content, replace it with ]]]]><![CDATA[>
        var escaped = str.toString().replace(/]]>/g, ']]]]><![CDATA[>');
        return '<![CDATA[' + escaped + ']]>';
    },

	// Helper function to escape xml special characters
	escapeXmlChars: function(str) {
		if (str === null || typeof str === 'undefined' || str == '') {
			return '';
		}
		str = String(str); 
		return str.replace(/&/g, '&amp;')
				.replace(/</g, '&lt;')
				.replace(/>/g, '&gt;')
				.replace(/"/g, '&quot;')
				.replace(/'/g, '&apos;');
	},

    //value of sca checkbox
    importScaFlaw: function(configId) {
        return this._getConfig(configId).import_sca;
    },
    //value of sast checkbox
    importSastFlaw: function(configId) {
        return this._getConfig(configId).import_sast;
    },
    //value of kics checkbox
    importKicsFlaw: function(configId) {
        return this._getConfig(configId).import_kics;
    },
    //value of Container Security checkbox
    importContainerSecurityFlaw: function(configId) {
        return this._getConfig(configId).include_container_security;
    },
    //value of API security checkbox
    importApiSecurityFlaw: function(configId) {
        return this._getConfig(configId).include_api_security;
    },

    //value of OSSF Scorecard	 checkbox
    importScoreCardFlaw: function(configId) {
        return this._getConfig(configId).include_ossf_scorecard;
    },

    //value of Secret Detection checkbox
    importSecretDetectionFlaw: function(configId) {
        return this._getConfig(configId).include_secret_detection;
    },
    //validate XML
    validateXML: function(body, errorNodeName) {
        if (!body) return;
        var doc = new XMLDocument2();
        doc.parseXML(body);
        var err = null;
        try {
            var root = doc.getFirstNode('/' + doc.getDocumentElement().getNodeName());
            if (errorNodeName && root.getNodeName() == errorNodeName)
                err = root.getTextContent();
            else
                doc.getNextNode(root);
        } catch (e) {
            throw 'XML document syntax invalid';
        }
        if (err)
            throw this.MSG + 'Error: ' + err;
    },

    type: 'CheckmarxOneUtilBase'
};