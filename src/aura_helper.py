import requests
import re, json
import traceback
import time
import random
import string
from colored_logger import logger
from urllib.parse import urlparse
from urllib3.exceptions import InsecureRequestWarning
from http.cookies import SimpleCookie

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.16; rv:85.0) Gecko/210100101 Firefox/85.0'
AURA_ENDPOINTS = ['/s/sfsites/aura','/s/aura','/aura','/sfsites/aura']
MAX_RETRIES = 3
RETRY_DELAY = 2

class AuraActionHelper:
    @staticmethod
    def build_action(act_id, descriptor, params={}):
        return {
            'id':act_id,
            'descriptor':descriptor,
            'callingDescriptor':'UNKNOWN',
            'params':params
        }

    @staticmethod
    def build_context(fwuid, app, loaded):
        return json.dumps({
            "mode":"PROD",
            "fwuid":fwuid,
            "app":app,
            "loaded":loaded,
            "dn":[],
            "globals":{},
            "uad":False
        })

    @staticmethod
    def get_dummy_action():
        return AuraActionHelper.build_action(
            '242;a',
            'serviceComponent://ui.force.components.controllers.relatedList.RelatedListContainerDataProviderController/ACTION$getRecords',
            {"recordId":"Foobar"}
        )

    @staticmethod
    def get_dummy_context():
        return AuraActionHelper.build_context(
            "INVALID",
            "siteforce:loginApp2",
            {"APPLICATION@markup://siteforce:loginApp2":"siteforce:loginApp2"}
        )

class AuraActionResponse:
    def __init__(self, json_action):
        self.json_action = json_action
        self.id = None
        self.state = None
        self.return_value = None
        self.error_message = None
        self.parse_action_response()

    def parse_action_response(self):
        self.state = self.json_action['state']
        self.id = self.json_action['id']
        if self.is_success():
            self.return_value = self.json_action['returnValue']
        if self.is_error():
            error = self.json_action["error"][0]
            if 'event' in error:
                error_values = self.json_action["error"][0]["event"]["attributes"]["values"]
                if 'error' in error_values:
                    self.error_message = error_values['error']['message']
                elif 'message' in error_values:
                    self.error_message = error_values['message']
            elif 'message' in error:
                self.error_message = self.json_action["error"][0]["message"]

    def is_success(self):
        return self.state == 'SUCCESS'

    def is_error(self):
        return self.state == 'ERROR'

class AuraResponse:

    def __init__(self, response):
        self.response = response
        self.json_response = None
        self.actions_responses = []
        self.parse_response()

    def parse_response(self):
        if self.is_valid():
            self.json_response = self.response.json()
            for action in self.json_response.get('actions',[]):
                self.actions_responses.append(AuraActionResponse(action))
        else:
            logger.verbose(f"Invalid JSON response: {self.response.text}")

    def is_valid(self):
        try:
            self.response.json()
            return True
        except:
            return False

class AuraResponses:

    def __init__(self, aura_responses):
        self.aura_responses = aura_responses
        self.actions_responses = []
        self.aggregate_action_responses()

    def aggregate_action_responses(self):
        for aura_response in self.aura_responses:
            self.actions_responses += aura_response.actions_responses

class AuraHelper:

    def __init__(self, url, cookies, proxy, insecure, app, aura, context, token):

        self.url = url.rstrip('/')
        self.aura_token = 'undefined' if not token else token
        self.headers = {'User-Agent': USER_AGENT, 'Accept':'application/json'}
        self.session = requests.session()

        if cookies is None:
            logger.info('Cookies not supplied. This will only perform unauthenticated checks')
        else:
            parsed_cookies = SimpleCookie(cookies)
            for key, value in parsed_cookies.items():
                self.session.cookies.set(key, value)
            if self.session.cookies.get("sid") == None:
                logger.info("Cookies supplied but session cookie - SID not provided. This will only perform unauthenticated checks")

        self.objects = {}
        self.fwuid = None
        self.app = None
        self.csp_trusted = []
        self.gql_enabled = False
        self.session.verify = False if insecure else True
        self.session.proxies.update({} if not proxy else {'http':proxy, 'https':proxy})
   
        self.aura_endpoint = self.get_aura_endpoint() if not aura else aura
        logger.info(f'Using aura endpoint: {self.url}{self.aura_endpoint}')
        self.app = self.get_app() if not app else f"{self.url}/{app.lstrip('/')}"
        logger.info(f'Using app: {self.app}')
        self.context = self.get_context() if not context else context
        logger.debug(f'Using context: {self.context}')
        self.aura_token = self.get_aura_token() if not token else token
        logger.debug(f'Using token: {self.aura_token}')

    def build_post_body(self, actions=[], dummy=False):
        message = {
            'message': json.dumps({'actions':[AuraActionHelper.get_dummy_action()]}) if dummy else json.dumps({'actions':actions}),
            'aura.context': AuraActionHelper.get_dummy_context() if dummy else self.context,
            'aura.pageURI': 'unknown',
            'aura.token': self.aura_token
        }
        return message

    def send_aura_bulk(self, actions=[], chunk_size=100, dummy=False):
        chunk_size = min(chunk_size,100)
        actions = [actions] if not isinstance(actions, list) else actions
        actions_chunks = [actions[i:i+chunk_size] for i in range(0, len(actions), chunk_size)]
        aura_responses = []
        for i in range(len(actions_chunks)):
            chunk = actions_chunks[i]
            post_body = self.build_post_body(chunk)
            if len(actions_chunks) > 1:
                logger.info(f"Sending bulk aura actions chunk {i+1} of {len(actions_chunks)} (chunk size {len(chunk)}) ...")
            try:
                response = self._request_with_retry(f"{self.url}{self.aura_endpoint}", data=post_body)
                aura_response = AuraResponse(response)
                aura_responses.append(aura_response)
            except requests.exceptions.SSLError as e:
                logger.error("Error when sending aura request, try using parameter -k to ignore invalid certificates")
                logger.debug(traceback.format_exc())
            except requests.exceptions.ReadTimeout as e:
                if chunk_size > 1:
                    logger.error("Timeout when sending aura request, re-attempting to send the chunk slowly and without bulking...")
                    aura_responses += self.send_aura_bulk(chunk, chunk_size=1).aura_responses
        return AuraResponses(aura_responses)

    def _request_with_retry(self, url, data, timeout=90):
        last_exc = None
        for attempt in range(MAX_RETRIES):
            try:
                return self.session.post(url=url, headers=self.headers, data=data, timeout=timeout)
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                last_exc = e
                if attempt < MAX_RETRIES - 1:
                    logger.verbose(f"Request failed (attempt {attempt+1}/{MAX_RETRIES}), retrying in {RETRY_DELAY}s...")
                    time.sleep(RETRY_DELAY)
        raise last_exc

    def get_aura_endpoint(self):
        post_body = self.build_post_body(dummy=True)
        for endpoint in AURA_ENDPOINTS:
            try:
                post_request = self.session.post(f"{self.url}{endpoint}", allow_redirects=False, headers=self.headers, data=post_body)
                if 'markup://' in post_request.text:
                    return endpoint
                elif post_request.status_code == 301 and post_request.headers.get('Location'):
                    redir_url = post_request.headers.get('Location')
                    post_request = self.session.post(redir_url, allow_redirects=False, headers=self.headers, data=post_body)
                    if 'markup://' in post_request.text:
                        return urlparse(redir_url).path
            except requests.exceptions.SSLError:
                logger.error("Error when trying to retrieve aura endpoint, try using parameter -k to ignore invalid certificates")
            except requests.exceptions.ConnectionError:
                logger.error("Cannot reach the target URL, aborting...")
                logger.debug(traceback.format_exc())
                exit()
            except:
                logger.error("Error when trying to retrieve aura endpoint")
                logger.debug(traceback.format_exc())
                pass
        logger.critical('Could not identify aura endpoint.')
        exit()

    def get_context(self):
        response_body = self.session.get(self.app, allow_redirects=True, headers=self.headers)
        aura_encoded = re.search(r'\/s\/sfsites\/l\/([^\/]+fwuid[^\/]+)', response_body.text)
        context = AuraActionHelper.get_dummy_context()
        if aura_encoded is None:
            if ("window.location.href ='%s" % self.url) in response_body.text:
                location_url = re.search(r'window.location.href =\'([^\']+)', response_body.text)
                if location_url:
                    url = location_url.group(1)
                    try:
                        response_body = self.session.get(url, allow_redirects=True, headers=self.headers)
                    except Exception as e:
                        logger.error("Failed to access the redirect url")
                        raise
        fwuid = re.search(r'"fwuid":"([^"]+)', response_body.text)
        markup = re.search(r'"(APPLICATION@markup[^"]+)":"([^"]+)"', response_body.text)
        app = re.search(r'"app":"([^"]+)', response_body.text)
        if fwuid is None:
            post_body = self.build_post_body(dummy=True)
            retry_resp = self.session.post(f'{self.url}{self.aura_endpoint}', data=post_body, allow_redirects=True, headers=self.headers)
            resp_data = retry_resp.text
            fwuid_pattern = "Expected:(.*?) Actual"
            fwuid = re.search(fwuid_pattern, resp_data)

            if 'markup://aura:invalidSession' in resp_data:
                logger.critical('Invalid session when trying to get context, guest access might be disabled, aborting')
                exit()
            elif fwuid is None:
                json_resp_data = json.loads(resp_data)
                if 'context' in json_resp_data:
                    fwuid = json_resp_data['context']['fwuid']
                else:
                    logger.critical('No context found in response, aborting')
                    logger.debug(json_resp_data)
                    exit()
            else:
                fwuid = fwuid.group(1).strip()
            app_data = 'siteforce:loginApp2'
            context = AuraActionHelper.build_context(fwuid,app_data,{f"APPLICATION@markup://{app_data}":app_data})
        else:
            fwuid_str = fwuid.group(1)
            app_str = app.group(1) if app else "siteforce:loginApp2"
            markup_key = markup.group(1) if markup else f"APPLICATION@markup://siteforce:loginApp2"
            markup_val = markup.group(2) if markup else "siteforce:loginApp2"
            context = AuraActionHelper.build_context(fwuid_str, app_str, {markup_key: markup_val})

        return context


    def get_aura_token(self):
        logger.verbose('Retrieving aura token')
        response = self.session.get(f"{self.app}", allow_redirects=True, headers=self.headers)

        aura_token_pattern = r'eyJub[^";]+'
        aura_token = 'undefined'
        if aura_token_search := re.search(aura_token_pattern, response.text):
            aura_token = aura_token_search.group(0)
            logger.verbose(f'Found aura token in page: {aura_token}')
        elif 'set-cookie' in response.headers:
            if aura_token_search := re.search(aura_token_pattern, response.headers['set-cookie']):
                aura_token = aura_token_search.group(0)
                logger.verbose(f'Found aura token in cookie: {aura_token}')
        else:
            logger.warning(f'Aura token not found (probably because SID cookie was not supplied), using undefined token')

        return aura_token


    def get_app(self):
        logger.verbose('Retrieving app')
        for endpoint in AURA_ENDPOINTS:
            if endpoint in self.aura_endpoint:
                return f'{self.url}{self.aura_endpoint.replace(endpoint, "")}/s'
        if self.aura_endpoint == '/s' and '/aura' in AURA_ENDPOINTS:
            return f'{self.url}/s'
        logger.warning('Could not determine app path from aura endpoint, using default /s')
        return f'{self.url}/s'


    def get_objects(self):
        logger.verbose('Attempting to retrieve all objects and CSP trusted sites')
        action = AuraActionHelper.build_action("1;a","aura://HostConfigController/ACTION$getConfigData")
        objects = []
        try:
            action_response = self.send_aura_bulk(action).actions_responses[0]
            self.csp_trusted = action_response.return_value['cspTrustedSites']
            objects = list(action_response.return_value['apiNamesToKeyPrefixes'].keys())
            logger.info(f'Found {len(objects)} objects')
        except:
            logger.error("Error while retrieving objects and CSP trusted sites")
            logger.debug(traceback.format_exc())

        return objects

    def get_records(self, objects, fetch_all=False):

        results = {}
        actions = []
        for object_name in objects:
            params = {
                "entityNameOrId":object_name,
                "layoutType":"COMPACT",
                "pageSize": 250 if fetch_all else 1,
                "currentPage":1,
                "useTimeout":False,
                "getCount":True,
                "enableRowActions":False
            }
            action = AuraActionHelper.build_action(
                object_name,
                "serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems",
                params
            )

            actions.append(action)

        logger.info(f"Attempting to retrieve information for {len(objects)} objects")
        bulk_chunk_size = 5 if fetch_all else 100
        actions_responses = self.send_aura_bulk(actions, chunk_size=bulk_chunk_size).actions_responses
        for action_response in actions_responses:
            object_name = action_response.id
            if action_response.is_success():
                total_count = action_response.return_value.get('totalCount') or 0
                records = action_response.return_value.get('items', [])
                results[object_name] = {'records': records, 'total_count': total_count}
                
                if fetch_all:
                    results[object_name]['raw_metadata'] = [action_response.return_value]
                    
                    page_size = 250
                    current_page = 1
                    while len(results[object_name]['records']) < total_count:
                        current_page += 1
                        logger.info(f"Fetching page {current_page} for {object_name} (REST)...")
                        params = {
                            "entityNameOrId":object_name,
                            "layoutType":"COMPACT",
                            "pageSize": page_size,
                            "currentPage": current_page,
                            "useTimeout":False,
                            "getCount":False,
                            "enableRowActions":False
                        }
                        next_action = AuraActionHelper.build_action(
                            object_name,
                            "serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems",
                            params
                        )
                        try:
                            next_resp = self.send_aura_bulk([next_action], chunk_size=1).actions_responses[0]
                            if next_resp.is_success():
                                new_records = next_resp.return_value.get('items', [])
                                if not new_records:
                                    break
                                results[object_name]['records'].extend(new_records)
                                results[object_name]['raw_metadata'].append(next_resp.return_value)
                            else:
                                logger.error(f'REST fetch failed for {object_name} page {current_page}: {next_resp.error_message}')
                                break
                        except Exception as e:
                            logger.error(f'Error retrieving page {current_page} for {object_name} via REST: {e}')
                            break
                    
            elif action_response.is_error():
                logger.error(f'Could not retrieve records for {object_name}: {action_response.error_message}')

        logger.info(f'Retrieved information for {len(results)} objects')
        return results

    def get_records_ui_list(self, objects):

        results = set()
        objects_with_views = {}
        actions = []
        for i in range(len(objects)):

            object_name = objects[i]

            action = AuraActionHelper.build_action(
                object_name,
                "serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews",
                {
                    "scope":object_name,
                    "maxMruResults":10,
                    "maxAllResults":20
                }
            )
            actions.append(action)

        logger.verbose(f"Attempting to retrieve UI lists for {len(objects)} objects")
        actions_responses = self.send_aura_bulk(actions).actions_responses
        for action_response in actions_responses:

            object_name = action_response.id
            try:
                if action_response.is_success() and len(action_response.return_value.get('listViews', [])) > 0:
                    objects_with_views[object_name] = action_response
                elif action_response.is_error():
                    logger.debug(f'Error while retrieving UI lists: {action_response.error_message}')
            except:
                logger.error(f'Unhandled error while retrieving UI record lists for object {object_name}')
                logger.debug(traceback.format_exc())

        if len(objects_with_views) > 0:
            logger.info("Checking accessible views for each object")
            
            actions = []

            for obj in objects_with_views:
                
                try:
                    for filter in objects_with_views[obj].return_value['listViews']:
                        action = AuraActionHelper.build_action(
                            f'{obj};{filter["name"]}',
                            "serviceComponent://ui.force.components.controllers.lists.listViewDataManager.ListViewDataManagerController/ACTION$getItems",
                            {
                                "filterName":filter['name'],
                                "entityName":obj,
                                "pageSize":50,
                                "layoutType":"LIST",
                                "getCount":True,
                                "enableRowActions":False,
                                "offset":0
                            }
                        )

                        actions.append(action)
            
                except:
                    logger.error(f'Unhandled error while retrieving UI record list for object {object_name}')

            actions_responses = self.send_aura_bulk(actions).actions_responses

            for action_response in actions_responses:
                try:
                    object_name,filter_name = action_response.id.split(";")
                    if action_response.is_success() and len(action_response.return_value['recordIdActionsList']) > 0:
                        logger.verbose(f'Identified accessible record list for {object_name} for filter {filter_name}')
                        results.add(f'{self.app}/recordlist/{object_name}/Default')
                except:
                    logger.debug(f'Error while retrieveing parsing UI list response')

        else:
            logger.info(f'No UI record lists for the targeted objects')

        if len(results) > 0:
            logger.warning(f'Found {len(results)} UI record lists for the targeted objects, please check these URLs manually as they could display sensitive records')
        
        return list(results)

    def get_object_home_urls(self):

        logger.verbose('Attempting to retrieve object home URLs')
        action = AuraActionHelper.build_action(
            "17;a",
            "serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData",
        )

        results = []
        try:
            action_response = self.send_aura_bulk(action).actions_responses[0]
            if action_response.is_success():
                results = action_response.json_action['components'][0]['model']['apiNameToObjectHomeUrls']
                logger.warning(f'Found {len(results)} object home URLs, please check these URLs manually as they could contain sensitive panels')
            elif action_response.is_error():
                logger.verbose(f'Could not retrieve object home URLs: {action_response.error_message}')
        except:
            logger.error('Error while retrieving object home URLs')
            logger.debug(traceback.format_exc())

        return results

    def check_self_registration_enabled(self):

        logger.verbose('Checking if self-registration is enabled')
        actions = [
              AuraActionHelper.build_action("1", "apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled"),
            AuraActionHelper.build_action("2", "apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl")
        ]

        try:
            actions_responses = self.send_aura_bulk(actions).actions_responses
            is_enabled_response = actions_responses[0]
            url_response = actions_responses[1]
            if is_enabled_response.is_success() and is_enabled_response.return_value:
                selfreg_url = url_response.return_value
                logger.warning(f'Self-registration is enabled and URL is {selfreg_url}')
                return selfreg_url
            else:
                logger.info(f'Self-registration is not enabled')
        except:
            logger.error('Error while checking for self-registration, if you are using a SID cookie it is usually normal behavior')
            logger.debug(traceback.format_exc())

        return None

    def check_graphql_enabled(self):

        logger.verbose('Checking if GraphQL queries can be used')
        action = AuraActionHelper.build_action(
            "GraphQL",
            "aura://RecordUiController/ACTION$executeGraphQL",
            {
                "queryInput":
                {
                    "operationName":"getUsersCount",
                    "query":"query getUsersCount{uiapi{query{User{totalCount}}}}",
                    "variables":{}
                }
            }
        )

        try:
            action_response = self.send_aura_bulk(action).actions_responses[0]
            if action_response.is_success():
                return_value = action_response.return_value
                if 'errors' in return_value and len(return_value['errors']) > 0:
                    logger.debug(f"GraphQL is enabled, but it does not seem like the user can use it, error message: {return_value['errors']['message']}")
                else:
                    logger.verbose("GraphQL is enabled, will try to prioritize it's use")
                    self.gql_enabled = True
            elif action_response.is_error():
                try:
                    logger.verbose(f"GraphQL is not available: {action_response.error_message}")
                except:
                    logger.verbose('GraphQL is not available')
            else:
                raise Exception(f'Unknown error when checking if GraphQL is enabled')
        except Exception as e:
            logger.error('Error while checking if GraphQL is enabled')
            logger.debug(traceback.format_exc())

    def get_graphql_fields_for_objects(self, objects):
        logger.info(f"Retrieving field names for {len(objects)} objects using GraphQL")
        banned_fields = ["CloneSourceId"]
        banned_types = ["ADDRESS","ANYTYPE","COMPLEXVALUE"]
        object_fields_map = {}

        total_chunks = (len(objects) - 1) // 100 + 1
        for i in range(0, len(objects), 100):
            logger.info(f"Retrieving fields for objects chunk {i//100 + 1} of {total_chunks}...")
            batch = objects[i:i+100]

            formatted_object_names = json.dumps(batch,separators=(',', ':'))
            action = AuraActionHelper.build_action(
                '1;fields',
                'aura://RecordUiController/ACTION$executeGraphQL',
                {
                    'queryInput':{
                        'operationName':'getFields',
                        'query':'query getFields{uiapi{objectInfos(apiNames:%s){ApiName,fields{ApiName,dataType}}}}' % (formatted_object_names),
                        'variables':{},
                    }
                }
            )
            action_response = self.send_aura_bulk(action).actions_responses[0]
            if not action_response.is_success():
                logger.error('Error while retrieving field names with GraphQL')
                return None

            objects_infos = filter(None, action_response.return_value['data']['uiapi']['objectInfos'])
            object_fields_map.update({
                x['ApiName']: [
                    y['ApiName'] for y in x['fields']
                    if y['dataType'] not in banned_types and y['ApiName'] not in banned_fields
                ]
                for x in objects_infos
            })
        return object_fields_map

    def get_object_count_graphql(self, objects, make_chunks=True):
        logger.info(f"Counting number of records for {len(objects)} objects using GraphQL")
        chunk_size = 10 if make_chunks else 1
        objects_chunks = [objects[i:i+chunk_size] for i in range(0, len(objects), chunk_size)]
        actions_responses = []
        for i, chunk in enumerate(objects_chunks):
            if len(objects_chunks) > 1:
                logger.info(f"Counting object records chunk {i+1} of {len(objects_chunks)}...")
            total_count_query = "".join([f"{object_name}{{totalCount}}" for object_name in chunk])
            action = AuraActionHelper.build_action(
                '1;a',
                'aura://RecordUiController/ACTION$executeGraphQL',
                {
                    'queryInput':{
                        'operationName':'getCount',
                        'query':'query getCount{uiapi{query{%s}}}' % (total_count_query),
                        'variables':{},
                    }
                }
            )
            try:
                actions_responses += self.send_aura_bulk([action]).actions_responses
            except requests.exceptions.ReadTimeout:
                logger.error("Timeout when trying to count records, one object might have too many records, counting object records one by one...")
                for obj_name in chunk:
                    action = AuraActionHelper.build_action(
                        '1;a',
                        'aura://RecordUiController/ACTION$executeGraphQL',
                        {
                            'queryInput':{
                                'operationName':'getCount',
                                'query':'query getCount{uiapi{query{%s{totalCount}}}}' % (obj_name),
                                'variables':{},
                            }
                        }
                    )
                    try:
                        actions_responses += self.send_aura_bulk([action], chunk_size=1).actions_responses
                    except requests.exceptions.ReadTimeout:
                        logger.error(f"Timeout when trying to count records of {obj_name}, might have too many records")
                        object_count_map = {obj_name:-1}

        object_count_map = {}
        all_failed_chunks = []
        for action_response in actions_responses:
            str_response = json.dumps(action_response.return_value)
            if 'uiapi' in action_response.return_value['data']:
                query_response = action_response.return_value['data']['uiapi']['query']
                for obj_name in query_response.keys():
                    if query_response[obj_name]:
                        object_count_map[obj_name] = query_response[obj_name]['totalCount']
                    elif query_response[obj_name] is None:
                        for error in action_response.return_value.get('errors', []):
                            paths = error.get('paths', []) if isinstance(error, dict) else []
                            if 'OPERATION_TOO_LARGE' in error.get('message', '') and len(paths) == 3 and paths[2] == obj_name:
                                logger.verbose(f'{obj_name} caused OPERATION_TOO_LARGE, it likely has too many records, setting count at -1')
                                object_count_map[obj_name] = -1
                            else:
                                logger.debug(f'Ignoring {obj_name} because of: {error["message"]}')
            elif 'ValidationError' in str_response:
                if make_chunks:
                    error_field_regex = r'FieldUndefined:[^\'"]+[\'"]([^\'"]+)[\'"]'
                    if error_fields := re.findall(error_field_regex, str_response):
                        failed_chunks = [chunk for chunk in objects_chunks for error_field in error_fields if error_field in chunk]
                        for failed_chunk in failed_chunks:
                            all_failed_chunks += failed_chunk
            else:
                logger.debug("Unhandled error when getting total count for objects with GraphQL: "+json.dumps(action_response.return_value))
        if all_failed_chunks:
            logger.verbose(f'Resending failed chunks while counting records with GraphQL: {all_failed_chunks}')
            failed_chunks_count_map = self.get_object_count_graphql(all_failed_chunks, make_chunks=False)
            object_count_map.update(failed_chunks_count_map)
        return object_count_map

    def get_records_graphql(self, objects, records_per_action=2000, fetch_all=False):
        results = {}

        object_fields_map = self.get_graphql_fields_for_objects(objects)
        uiapi_objects = list(object_fields_map.keys())
        logger.info(f"{len(uiapi_objects)} objects accessible with GraphQL through uiapi")

        logger.info("Hang tight - this may take a while")

        object_count_map = self.get_object_count_graphql(uiapi_objects)
        objects_with_records = [object_name for object_name in object_count_map if object_count_map[object_name] != 0]
        results = {k: {'records': [], 'total_count': v} for k, v in object_count_map.items() if v != 0}
        
        logger.info(f"{len(objects_with_records)} objects with records for a total of {sum(object_count_map.values())} records")

        if fetch_all and len(objects_with_records) > 0:
            logger.info(f"Fetching actual records for {len(objects_with_records)} objects via GraphQL...")
            for i, object_name in enumerate(objects_with_records):
                if object_name not in object_fields_map or len(object_fields_map[object_name]) == 0:
                    continue
                
                logger.info(f"Fetching records for {object_name} ({i+1}/{len(objects_with_records)})...")
                fields = object_fields_map[object_name]
                fields_str = ",".join([f"{f}{{value}}" for f in fields[:100] if f != "Id"])
                node_fields = f"Id,{fields_str}" if fields_str else "Id"
                
                has_next_page = True
                last_id = None
                page_num = 1
                
                while has_next_page:
                    where_str = ''
                    if last_id:
                        where_str = ', where: { Id: { gt: "%s" } }' % last_id
                        
                    query_str = 'query getRecords{uiapi{query{%s(first:%d%s, orderBy: { Id: { order: ASC } }){edges{node{%s}}}}}}' % (object_name, records_per_action, where_str, node_fields)
                    
                    action = AuraActionHelper.build_action(
                        object_name,
                        'aura://RecordUiController/ACTION$executeGraphQL',
                        {
                            'queryInput':{
                                'operationName':'getRecords',
                                'query': query_str,
                                'variables':{},
                            }
                        }
                    )
                    
                    try:
                        action_response = self.send_aura_bulk([action], chunk_size=1).actions_responses[0]
                        if action_response.is_success():
                            query_data = action_response.return_value.get('data', {}).get('uiapi', {}).get('query', {})
                            if object_name in query_data and query_data[object_name]:
                                obj_data = query_data[object_name]
                                edges = obj_data.get('edges', [])
                                
                                records = [edge.get('node', {}) for edge in edges]
                                if not records:
                                    has_next_page = False
                                    break
                                    
                                if 'records' not in results[object_name] or not isinstance(results[object_name].get('raw_metadata'), list):
                                    results[object_name]['records'] = []
                                    results[object_name]['raw_metadata'] = []
                                    
                                results[object_name]['records'].extend(records)
                                results[object_name]['raw_metadata'].append(action_response.return_value)
                                
                                if len(records) > 0:
                                    page_num += 1
                                    last_id_node = records[-1].get('Id')
                                    new_last_id = last_id_node.get('value') if isinstance(last_id_node, dict) else last_id_node
                                    if not new_last_id or new_last_id == last_id:
                                        logger.debug(f"Cannot deep paginate {object_name} further: missing or duplicated Id ({new_last_id}).")
                                        has_next_page = False
                                    else:
                                        last_id = new_last_id
                                        has_next_page = True
                                        logger.info(f"Fetching page {page_num} for {object_name} (GraphQL deep paginating after {last_id})...")
                                else:
                                    has_next_page = False
                            else:
                                logger.error(f'GraphQL query returned valid body but no object node for {object_name}.')
                                has_next_page = False
                        elif action_response.is_error():
                            logger.error(f'GraphQL fetch failed for {object_name}: {action_response.error_message}')
                            has_next_page = False
                    except Exception as e:
                        logger.error(f'Error retrieving {object_name} records via GraphQL: {e}')
                        has_next_page = False
        
        return results

    def get_custom_controllers(self):
        parsed_url = urlparse(self.app)
        req_url = f'{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}'
        resp = self.session.get(req_url)
        response_text = resp.text
        custom_controllers = {}
        endpoint_pattern = r'src="([^"]*)"'
        auracmp_pattern = r'/auraCmdDef\?[^"\']+'
        custom_controller_pattern = r'apex://[a-zA-Z0-9_-]+/ACTION\$[a-zA-Z0-9_-]+'

        endpoints = re.findall(endpoint_pattern, response_text) + re.findall(auracmp_pattern, response_text)
        logger.verbose('Endpoints that could contain information about custom controllers discovered, analyzing them')
        logger.debug(endpoints)

        found = False
        for endpoint in endpoints:
            if not 'http:' in endpoint and not 'https:' in endpoint:
                endpoint_url = f'{parsed_url.scheme}://{parsed_url.netloc}{endpoint}'
            else:
                endpoint_url = endpoint

            try:
                resp = self.session.get(endpoint_url)
                response_text = resp.text
                endpoint_controllers = re.findall(custom_controller_pattern, response_text)
                if endpoint_controllers:
                    custom_controllers[endpoint_url] = endpoint_controllers if endpoint_url not in custom_controllers else list(set(custom_controllers[endpoint_url] + endpoint_controllers))
            except:
                logger.debug(f'Error when processing URL {endpoint_url} during custom controllers check')

        if len(custom_controllers) == 0:
            logger.error('Did not find any custom controllers')
        else:
            logger.warning(f'Found {sum([len(v) for v in custom_controllers.values()])} custom controllers')

        return custom_controllers


    def build_soap_message(self, body):
        sid = self.session.cookies.get("sid")
        xml_header = '<?xml version="1.0" encoding="utf-8"?>'
        soap_env_header = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tns="http://soap.sforce.com/2006/04/metadata">'
        soap_session = f'<soapenv:Header><tns:SessionHeader><tns:sessionId>{sid}</tns:sessionId></tns:SessionHeader></soapenv:Header>'
        soap_env_footer = '</soapenv:Envelope>'
        return f'{xml_header}{soap_env_header}{soap_session}{body}{soap_env_footer}'


    def check_soap_api_enabled(self):
        logger.verbose('Checking if SOAP API is exposed (Require API enabled permission)')
        try:
            soap_req = self.session.post(f'{self.url}/services/Soap/u/35.0', headers={'Content-Type':'text/xml', 'SOAPAction': 'Empty'})
            if soap_req.status_code == 500 and 'text/xml' in soap_req.headers['Content-Type']:
                logger.info('SOAP API seems to be enabled, may require username and password authentication')
            else:
                logger.info('SOAP API does not seem to be exposed')
        except:
            logger.error('Error while querying the SOAP API')
            logger.debug(traceback.format_exc())


    def check_rest_api_enabled(self):
        logger.verbose('Checking if REST API is exposed (Require API enabled permission)')
        latest_rest_url = None
        try:
            latest_rest_url_req = self.session.get(f'{self.url}/services/data')
            latest_rest_url = latest_rest_url_req.json()[-1]['url']
            logger.verbose(f'Checking REST url using URL: {self.url}{latest_rest_url}')
        except:
            logger.error('Error while retrieving REST URL for latest version')
            logger.debug(traceback.format_exc())
            return False
        headers = {'Authorization': f'Bearer {self.session.cookies.get("sid")}'}
        try:
            rest_req = self.session.get(f'{self.url}{latest_rest_url}', headers=headers)
            if rest_req.status_code == 200:
                logger.info(f'REST API is accessible with the provided SID: {self.session.cookies.get("sid")}')
                return True
            else:
                logger.info(f'REST API is not accessible using the provided SID: {self.session.cookies.get("sid")}')
                return False
        except:
            logger.debug(traceback.format_exc())
            logger.error('Error while querying the REST request for latest version')
        return False

    def get_record_detail(self, object_name, record_id):
        action = AuraActionHelper.build_action(
            record_id,
            "aura://RecordUiController/ACTION$getRecord",
            {
                "recordId": record_id,
                "layoutType": "FULL",
                "modes": {"CREATE", "EDIT", "VIEW"},
                "useFullRecordLayout": True,
                "enableRecordLinks": False,
                "bypassNetworkFieldSecurity": False
            }
        )
        try:
            action_response = self.send_aura_bulk([action], chunk_size=1).actions_responses[0]
            if action_response.is_success():
                return action_response.return_value
            else:
                logger.debug(f'getRecord failed for {object_name}/{record_id}: {action_response.error_message}')
        except Exception as e:
            logger.debug(f'Error getting record detail for {object_name}/{record_id}: {e}')
        return None

    def get_records_full(self, records_data, target_objects=None):
        logger.info('Attempting to extract FULL field data for discovered records via getRecord...')
        results = {}
        actions = []

        for obj_name, data in records_data.items():
            if target_objects and obj_name not in target_objects:
                continue
            if data.get('records'):
                for record in data.get('records', []):
                    rid = record.get('Id')
                    if isinstance(rid, dict):
                        rid = rid.get('value')
                    if rid:
                        action = AuraActionHelper.build_action(
                            rid,
                            "aura://RecordUiController/ACTION$getRecord",
                            {
                                "recordId": rid,
                                "layoutType": "FULL",
                                "modes": {"CREATE", "EDIT", "VIEW"},
                                "useFullRecordLayout": True,
                                "enableRecordLinks": False,
                                "bypassNetworkFieldSecurity": False
                            }
                        )
                        actions.append((obj_name, rid, action))

        if not actions:
            logger.info('No record IDs found to expand')
            return results

        logger.info(f'Requesting FULL layout for {len(actions)} records...')
        chunk_size = 10
        raw_actions = [a[2] for a in actions]

        for i in range(0, len(raw_actions), chunk_size):
            chunk = raw_actions[i:i+chunk_size]
            try:
                responses = self.send_aura_bulk(chunk, chunk_size=chunk_size).actions_responses
                for j, resp in enumerate(responses):
                    idx = i + j
                    if idx >= len(actions):
                        break
                    obj_name, rid, _ = actions[idx]
                    if resp.is_success():
                        if obj_name not in results:
                            results[obj_name] = []
                        results[obj_name].append({
                            'recordId': rid,
                            'recordData': resp.return_value
                        })
                    else:
                        logger.debug(f'Full detail failed for {obj_name}/{rid}')
            except Exception as e:
                logger.debug(f'Error in full detail chunk: {e}')

        logger.info(f'Retrieved FULL details for {sum(len(v) for v in results.values())} records across {len(results)} objects')
        return results

    def get_records_list_action(self, objects):
        results = {}
        actions = []
        for object_name in objects:
            action = AuraActionHelper.build_action(
                object_name,
                "serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getList",
                {
                    "entityNameOrId": object_name,
                    "layoutType": "LIST",
                    "pageSize": 250,
                    "currentPage": 1,
                    "useTimeout": False,
                    "getCount": True,
                    "enableRowActions": False
                }
            )
            actions.append(action)

        logger.info(f'Attempting getList fallback for {len(objects)} objects...')
        responses = self.send_aura_bulk(actions, chunk_size=100).actions_responses
        for resp in responses:
            obj_name = resp.id
            if resp.is_success():
                total = resp.return_value.get('totalCount', 0)
                items = resp.return_value.get('items', [])
                if items or total > 0:
                    results[obj_name] = {'records': items, 'total_count': total}
            else:
                logger.debug(f'getList failed for {obj_name}: {resp.error_message}')

        return results

    def enumerate_users_forgot_password(self):
        logger.info('Checking forgot password endpoint for user enumeration...')
        actions = [
            AuraActionHelper.build_action(
                "forgot",
                "apex://SiteLoginController/ACTION$forgotPassword",
                {"username": "test@test.com"}
            ),
            AuraActionHelper.build_action(
                "exists",
                "apex://SiteRegisterController/ACTION$checkEmailAvailability",
                {"email": "admin@" + urlparse(self.url).netloc.split('.')[-2] + ".com"}
            ),
        ]

        findings = {}
        try:
            responses = self.send_aura_bulk(actions).actions_responses
            for resp in responses:
                if resp.is_success():
                    if resp.id == 'forgot':
                        findings['forgotPassword'] = 'accessible - user enumeration possible'
                        logger.warning('Forgot password endpoint is accessible (guest) - user enumeration possible')
                    elif resp.id == 'exists':
                        findings['emailCheck'] = 'accessible'
                        logger.warning('Email availability check accessible')
                elif resp.is_error():
                    findings[resp.id] = f'blocked: {resp.error_message}'
                else:
                    findings[resp.id] = 'unknown state'
        except Exception as e:
            logger.debug(f'Error during user enumeration check: {e}')

        return findings

    def query_graphql_filtered(self, object_name, filters=None, fields=None, limit=50):
        where_clause = ''
        if filters:
            filter_parts = []
            for key, val in filters.items():
                filter_parts.append('%s: { eq: "%s" }' % (key, val))
            if filter_parts:
                where_clause = ', where: { %s }' % ' ,'.join(filter_parts)

        field_str = 'Id'
        if fields:
            field_str = ','.join(fields[:50])

        query_str = 'query filteredQuery{uiapi{query{%s(first:%d%s, orderBy: { Id: { order: ASC } }){edges{node{%s}}}}}}' % (
            object_name, limit, where_clause, field_str
        )

        action = AuraActionHelper.build_action(
            object_name,
            'aura://RecordUiController/ACTION$executeGraphQL',
            {
                'queryInput': {
                    'operationName': 'filteredQuery',
                    'query': query_str,
                    'variables': {},
                }
            }
        )

        try:
            action_response = self.send_aura_bulk([action], chunk_size=1).actions_responses[0]
            if action_response.is_success():
                query_data = action_response.return_value.get('data', {}).get('uiapi', {}).get('query', {})
                if object_name in query_data and query_data[object_name]:
                    edges = query_data[object_name].get('edges', [])
                    return [edge.get('node', {}) for edge in edges]
            elif action_response.is_error():
                logger.debug(f'Filtered GraphQL query failed for {object_name}: {action_response.error_message}')
        except Exception as e:
            logger.debug(f'Error in filtered GraphQL query for {object_name}: {e}')

        return []

    def get_content_files(self, content_version_ids):
        downloaded = {}
        if not self.session.cookies.get("sid"):
            logger.info('No SID cookie - cannot download ContentVersion files without auth')
            return downloaded

        for cv_id in content_version_ids:
            if isinstance(cv_id, dict):
                cv_id = cv_id.get('value', cv_id)

            action = AuraActionHelper.build_action(
                str(cv_id),
                "aura://FileController/ACTION$getFile",
                {
                    "recordId": str(cv_id),
                    "field": "VersionData"
                }
            )

            try:
                action_response = self.send_aura_bulk([action], chunk_size=1).actions_responses[0]
                if action_response.is_success():
                    downloaded[str(cv_id)] = action_response.return_value
                    logger.info(f'Downloaded ContentVersion file: {cv_id}')
                else:
                    logger.debug(f'Cannot download {cv_id}: {action_response.error_message}')
            except Exception as e:
                logger.debug(f'Error downloading {cv_id}: {e}')

        return downloaded

    def discover_additional_controllers(self):
        logger.info('Probing additional Apex controllers...')
        controller_actions = {
            'community_list': ('apex://CommunityManagementController/ACTION$getCommunityList', {}),
            'community_users': ('apex://CommunityManagementController/ACTION$getCommunityUsers', {"communityId": "0DB"}),
            'site_url_mapping': ('apex://SiteUrlMappingController/ACTION$getAllSiteUrls', {}),
            'login_discovery': ('apex://SiteLoginController/ACTION$getLoginDiscoveryUrl', {}),
            'site_register_config': ('apex://SiteRegisterController/ACTION$getRegistrationConfig', {}),
            'knowledge_articles': ('connectApi://KnowledgeArticleController/ACTION$getArticle', {"articleId": "000000000000000"}),
            'content_detail': ('connectApi://ContentHubController/ACTION$getContentDetail', {"contentId": "000000000000000"}),
            'aura_application': ('aura://ComponentController/ACTION$getApplication', {"name": "one:one"}),
            'component_descriptor': ('aura://ComponentController/ACTION$getComponent', {"name": "ui:inputText", "attributes": {}}),
            'record_action_overrides': ('aura://RecordUiController/ACTION$getRecordActionOverrides', {"entityName": "User"}),
        }

        findings = {}
        actions = []
        for name, (descriptor, params) in controller_actions.items():
            action = AuraActionHelper.build_action(name, descriptor, params)
            actions.append(action)

        try:
            responses = self.send_aura_bulk(actions).actions_responses
            for resp in responses:
                if resp.is_success():
                    findings[resp.id] = 'accessible'
                    logger.warning(f'Additional controller accessible: {resp.id}')
                else:
                    findings[resp.id] = f'blocked: {resp.error_message}'
                    logger.debug(f'Controller {resp.id} not accessible: {resp.error_message}')
        except Exception as e:
            logger.debug(f'Error probing additional controllers: {e}')

        return findings

    def try_self_registration(self, email_domain=None):
        logger.info('Attempting self-registration...')

        config_action = AuraActionHelper.build_action(
            "cfg",
            "apex://SiteRegisterController/ACTION$getRegistrationConfig",
            {}
        )
        try:
            cfg_resp = self.send_aura_bulk([config_action]).actions_responses[0]
            if not cfg_resp.is_success():
                logger.info(f'Self-registration not configured/accessible: {cfg_resp.error_message}')
                return None
            config = cfg_resp.return_value
            logger.info(f'Self-registration config retrieved')
            logger.verbose(json.dumps(config)[:500])
        except Exception as e:
            logger.info(f'Self-registration check failed: {e}')
            return None

        if not email_domain:
            email_domain = urlparse(self.url).netloc.split('.')[-2] + '.com'
        rand_str = ''.join(random.choice(string.ascii_lowercase) for _ in range(8))
        first_name = f'Test{rand_str[:4].capitalize()}'
        last_name = f'User{rand_str[4:].capitalize()}'
        email = f'{rand_str}@{email_domain}'
        username = email
        password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(16))

        logger.warning(f'Registering: {first_name} {last_name} <{email}>')

        field_map = config.get('fieldMap', {}) if isinstance(config, dict) else {}
        reg_params = {}

        name_mappings = {
            'firstName': first_name, 'FirstName': first_name,
            'lastName': last_name, 'LastName': last_name,
            'email': email, 'Email': email, 'emailAddress': email,
            'username': username, 'Username': username,
            'password': password, 'Password': password,
            'confirmPassword': password, 'ConfirmPassword': password,
            'companyName': 'TestCorp', 'CompanyName': 'TestCorp',
            'CommunityNickname': rand_str, 'communityNickname': rand_str,
            'Alias': rand_str[:8], 'alias': rand_str[:8],
        }

        reg_actions_to_try = [
            ("apex://SiteRegisterController/ACTION$registerUser", {}),
            ("apex://SiteRegisterController/ACTION$register", {}),
            ("apex://SiteRegisterController/ACTION$createPortalUser", {}),
            ("apex://SiteRegisterController/ACTION$submitRegistration", {}),
            ("apex://LightningSelfRegisterController/ACTION$selfRegister", {}),
        ]

        registered = False
        new_sid = None

        for descriptor, base_params in reg_actions_to_try:
            try:
                params = dict(base_params)
                params.update(name_mappings)
                params.update(reg_params)

                action = AuraActionHelper.build_action("reg", descriptor, params)
                resp = self.send_aura_bulk([action]).actions_responses[0]

                if resp.is_success():
                    logger.warning(f'Registration successful via {descriptor}!')
                    registered = True

                    reg_session = self.session
                    new_sid = reg_session.cookies.get("sid")
                    if new_sid:
                        logger.warning(f'Got SID from registration: {new_sid[:30]}...')

                    break
                elif resp.is_error():
                    msg = str(resp.error_message)[:200]
                    logger.verbose(f'{descriptor.split("/ACTION$")[-1]} failed: {msg}')

                    rv = resp.return_value if hasattr(resp, 'return_value') and resp.return_value else None
                    if rv and isinstance(rv, str) and 'http' in rv:
                        logger.verbose(f'Got redirect: {rv}')
                        try:
                            redir_resp = self.session.get(rv, allow_redirects=True)
                            new_sid = self.session.cookies.get("sid")
                            if new_sid:
                                logger.warning(f'Got SID after following redirect: {new_sid[:30]}...')
                                registered = True
                                break
                        except:
                            pass
            except Exception as e:
                logger.verbose(f'Error in registration attempt via {descriptor}: {e}')

        if not registered:
            logger.info('Trying page-form based registration...')
            try:
                reg_page_url = f'{self.app}/SelfRegister'
                page_resp = self.session.get(reg_page_url, allow_redirects=True)

                vf_pattern = r'<input[^>]+name="([^"]+)"[^>]+value="([^"]*)"'
                hidden_fields = re.findall(vf_pattern, page_resp.text)

                if hidden_fields:
                    form_data = dict(hidden_fields)
                    form_data.update({
                        'firstName': first_name,
                        'lastName': last_name,
                        'email': email,
                        'password': password,
                        'confirmPassword': password,
                        'companyName': 'TestCorp',
                    })

                    post_url = reg_page_url
                    action_match = re.search(r'action="([^"]+)"', page_resp.text)
                    if action_match:
                        post_url = action_match.group(1)
                        if post_url.startswith('/'):
                            parsed = urlparse(self.url)
                            post_url = f'{parsed.scheme}://{parsed.netloc}{post_url}'

                    reg_resp = self.session.post(post_url, data=form_data, allow_redirects=True)
                    new_sid = self.session.cookies.get("sid")
                    if new_sid:
                        logger.warning(f'Got SID via form registration: {new_sid[:30]}...')
                        registered = True
            except Exception as e:
                logger.debug(f'Form registration failed: {e}')

        if not registered:
            logger.warning('All self-registration methods failed')
            return None

        result = {
            'sid': new_sid,
            'email': email,
            'username': username,
            'password': password,
            'firstName': first_name,
            'lastName': last_name,
        }
        return result
