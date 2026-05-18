from aura_helper import AuraHelper
from datetime import date
from colored_logger import init_logger,logger,add_logging_level
import logging
import sys
import argparse
import json
import os
import signal
from urllib.parse import parse_qs

def audit(url, cookies, object_list, output_dir, proxy, fetch_max_data=False, insecure=False, app=None, aura_path="/aura", context=None, token="null", no_gql=False, experimental=False):

	aura = AuraHelper(url=url, cookies=cookies, proxy=proxy, insecure=insecure, app=app, aura=aura_path, context=context, token=token)

	aura.check_self_registration_enabled()
	aura.check_rest_api_enabled()
	aura.check_soap_api_enabled()
	if not no_gql:
		aura.check_graphql_enabled()

	custom_controllers = aura.get_custom_controllers()

	all_objects = aura.get_objects()
	objects = all_objects
	if object_list:
		all_objects_lower = [x.lower() for x in all_objects]
		valid_objects = [x for x in object_list if x.lower() in all_objects_lower]
		invalid_objects = [x for x in object_list if x.lower() not in all_objects_lower]
		if valid_objects:
			objects = valid_objects
			logger.info(f'Targeting valid objects provided: {",".join(valid_objects)}')
		else:
			logger.error('No valid objects provided with -l')
			exit()
		if invalid_objects:
			logger.warning(f'Ignoring invalid objects: {",".join(invalid_objects)}')
	if objects is None:
		logger.error('Could not find any objects')
		exit()

	all_records = []
	all_records_gql = []
	all_records = aura.get_records(objects, fetch_all=fetch_max_data)
	if aura.gql_enabled:
		all_records_gql = aura.get_records_graphql(objects, records_per_action=100, fetch_all=fetch_max_data)
	all_ui_lists = dict()

	recordlists = aura.get_records_ui_list(objects)

	home_urls = aura.get_object_home_urls()
	
	exploit_results = {}
	auth_aura = None
	if experimental:
		logger.warning('--- Experimental mode enabled ---')

		self_reg = aura.try_self_registration()
		if self_reg and self_reg.get('sid'):
			logger.warning(f'--- Re-running audit with authenticated session (SID: {self_reg["sid"][:20]}...) ---')
			auth_cookies = f'sid={self_reg["sid"]}'
			exploit_results['self_reg'] = {
				'email': self_reg['email'],
				'username': self_reg['username'],
				'password': self_reg['password'],
				'sid': self_reg['sid'],
			}
			try:
				auth_aura = AuraHelper(url=url, cookies=auth_cookies, proxy=proxy, insecure=insecure, app=app, aura=aura_path, context=context, token=token)
				auth_aura.check_graphql_enabled()
				auth_all_objects = auth_aura.get_objects()
				auth_objects = [o for o in auth_all_objects if o in objects or o.lower() in [x.lower() for x in objects]]
				if not auth_objects:
					auth_objects = auth_all_objects

				auth_records = auth_aura.get_records(auth_objects, fetch_all=fetch_max_data)
				if auth_records:
					exploit_results['authenticated_records_summary'] = {k: v.get('total_count', 0) for k, v in auth_records.items() if v.get('total_count', 0) > 0}
					all_records.update(auth_records)

				if auth_aura.gql_enabled:
					auth_gql = auth_aura.get_records_graphql(auth_objects, records_per_action=100, fetch_all=fetch_max_data)
					if auth_gql:
						exploit_results['authenticated_gql_summary'] = {k: v.get('total_count', 0) for k, v in auth_gql.items() if v.get('total_count', 0) > 0}
						all_records_gql.update(auth_gql)

				full_details = auth_aura.get_records_full(all_records, target_objects=None)
				if full_details:
					exploit_results['auth_full_record_details'] = {k: len(v) for k, v in full_details.items()}

				targeted = auth_aura.query_graphql_filtered(
					'User',
					fields=['Id', 'Username', 'Email', 'FirstName', 'LastName', 'IsActive', 'ProfileId', 'UserType', 'LastLoginDate'],
					limit=500
				)
				if targeted:
					exploit_results['authenticated_users'] = targeted

			except Exception as e:
				logger.error(f'Authenticated re-audit failed: {e}')

		fallback_records = aura.get_records_list_action(objects)
		if fallback_records:
			logger.warning(f'getList recovered {len(fallback_records)} objects that getItems missed')
			exploit_results['getlist_fallback'] = fallback_records

		additional_ctrl = aura.discover_additional_controllers()
		if additional_ctrl:
			exploit_results['additional_controllers'] = additional_ctrl

		user_enum = aura.enumerate_users_forgot_password()
		if user_enum:
			exploit_results['user_enumeration'] = user_enum

		combined_records = {}
		combined_records.update(all_records)
		combined_records.update(all_records_gql)
		extractor = auth_aura if auth_aura else aura
		full_details = extractor.get_records_full(combined_records, target_objects=None)
		if full_details:
			exploit_results['full_record_details'] = {k: len(v) for k, v in full_details.items()}

		logger.info('Running targeted GraphQL queries...')
		targets = [
			('User', ['Id', 'Username', 'Email', 'FirstName', 'LastName', 'IsActive', 'ProfileId', 'UserType', 'LastLoginDate', 'CreatedDate']),
			('Account', ['Id', 'Name', 'Type', 'Industry', 'Phone', 'Website', 'OwnerId']),
			('Contact', ['Id', 'Name', 'Email', 'Phone', 'Title', 'AccountId']),
			('ContentVersion', ['Id', 'Title', 'FileExtension', 'ContentDocumentId', 'CreatedDate', 'OwnerId', 'FileType', 'ContentSize']),
			('KnowledgeArticleVersion', ['Id', 'Title', 'Summary', 'UrlName', 'LastPublishedDate', 'KnowledgeArticleId']),
		]
		query_aura = auth_aura if auth_aura else aura
		targeted_results = {}
		for obj_name, fields in targets:
			if obj_name in objects or obj_name.lower() in [o.lower() for o in objects]:
				records = query_aura.query_graphql_filtered(obj_name, fields=fields, limit=500)
				if records:
					targeted_results[obj_name] = records
					logger.warning(f'Extracted {len(records)} {obj_name} records via targeted GraphQL')
		if targeted_results:
			exploit_results['targeted_graphql'] = targeted_results

		content_doc_ids = []
		for obj_name, data in combined_records.items():
			if obj_name in ('ContentVersion', 'ContentDocument') and data.get('records'):
				for rec in data.get('records', []):
					rid = rec.get('Id', {})
					if isinstance(rid, dict):
						rid = rid.get('value')
					if rid:
						content_doc_ids.append(rid)

		if content_doc_ids:
			logger.info(f'Attempting to download {len(content_doc_ids)} files...')
			downloaded = aura.get_content_files(content_doc_ids)
			if downloaded:
				exploit_results['downloaded_files'] = {k: 'downloaded' for k in downloaded}

	print('')
	print('--- Summary ---')
	print(draw_table(all_records))
	print('')
	if aura.gql_enabled:
		print('--- Summary GraphQL ---')
		print(draw_table(all_records_gql))
		print('')
	if experimental and exploit_results:
		print('--- Experimental Findings ---')
		print(json.dumps({k: f'{len(v)} items' if isinstance(v, (list, dict)) else v for k, v in exploit_results.items()}, indent=2))

	if not output_dir:
		while True:
			is_save = input('Would you like to save the results? (y/N): ')
			if is_save == 'y':
				output_dir = input('Please specify the relative or full path to directory you would like to save the results to: ')
				logger.info(f'Results have been saved to: {output_dir}')
				break
			elif is_save == 'N':
				logger.warning('Results were not saved')
				break
			else:
				logger.warning('Invalid choice, try again')

	if output_dir:
		write_records_to_directory(all_records, output_dir, "records")
		write_records_to_directory(all_records_gql, output_dir, "gql_records")
		write_misc_to_directory(recordlists, output_dir, sub_dir='misc',file_name='recordlists.json')
		write_misc_to_directory(home_urls, output_dir, sub_dir='misc',file_name='homeurls.json')
		write_misc_to_directory(aura.csp_trusted, output_dir, sub_dir='misc',file_name='csp_trusted_sites.json')
		write_misc_to_directory(custom_controllers, output_dir, sub_dir='misc',file_name='custom_controllers.json')
		if experimental and exploit_results:
			write_misc_to_directory(exploit_results, output_dir, sub_dir='misc', file_name='experimental_findings.json')

		logger.info(f'Please check the {output_dir} folder for retrieved records, object home URLs and records UI list record URLs')
		logger.warning('The object home URLs and records UI list need to be checked manually at the moment to verify whether any sensitive data or panel is available')


def write_records_to_directory(all_records, parent_dir, sub_dir):
	
	if len(all_records) == 0:
		return

	path_to_write = os.path.join(parent_dir, sub_dir)
	os.makedirs(path_to_write, exist_ok=True)

	logger.info(f'Writing record information to {path_to_write}')
	with open(os.path.join(path_to_write, f'summary.txt'), 'w') as f:
		f.write(draw_table(all_records))

	for object_name, data in all_records.items():
		if data.get('records') and len(data.get('records')) > 0:
			file_path = os.path.join(path_to_write, f'{object_name}.json')
			with open(file_path, 'w') as f:
				json.dump(data, f, indent=4)


def write_misc_to_directory(obj_to_write, parent_dir, sub_dir='misc', file_name=''):
	
	if len(obj_to_write) == 0:
		return

	path_to_write = os.path.join(parent_dir,sub_dir)
	os.makedirs(path_to_write, exist_ok=True)

	file_to_write = os.path.join(path_to_write, file_name)

	logger.info(f'Writing miscellaneous to {file_to_write}')

	with open(f'{file_to_write}', 'w') as f:
		json.dump(obj_to_write, f)

def draw_table(records):
	record_count = [
		[
			'Object Name',
			'Total Count'
		]
	]
	col_width = 15
	for object_name in records:
		retrievable = records[object_name]['total_count']
		if retrievable == 0:
			continue
		col_width = max(col_width,len(object_name)+1)
		record_count.append(
			[
				object_name,
				retrievable if retrievable != -1 else 'Unknown'
			]
        )
	table = ''
	for row_index in range(len(record_count)):
		table += ''.join(f'{x:<{col_width}}' for x in record_count[row_index]) + '\n'
	return table

def parse_http_request_file(http_req_file):

	http_request = ''

	with open(http_req_file, 'r') as req_file:
		http_request = [l.strip() for l in req_file.readlines()]

	request_line = http_request[0]
	aura_endpoint = request_line.split(" ")[1]

	if "?" in aura_endpoint:
		aura_endpoint = aura_endpoint.split("?", 1)[0]

	if not ('aura' in aura_endpoint and 'POST' in request_line) :
		logger.warning('Request file does not appear to be a POST request to aura!')

	headers = {}

	for line in http_request[1:]:

		if line.strip() == '':
			break

		key, value = line.split(':', 1)
		if key.lower().strip() == 'host':
			headers['host'] = value.strip()
		elif key.lower().strip() == 'cookie':
			headers['cookies'] = value.strip()
		else:
			continue

	body = parse_qs(http_request[-1])

	aura_context = body['aura.context'][0]
	parsed_context = json.loads(aura_context)

	aura_token = body['aura.token'][0]

	result = {
		'url':'https://' + headers['host'],
		'cookies': headers['cookies'],
		'context':aura_context,
		'aura_endpoint':aura_endpoint,
		'token':aura_token
	}

	return result

def main():

	parser = argparse.ArgumentParser(prog="python3 aura_cli.py")
	parser.add_argument("-u", "--url", help="Root URL of Salesforce application to audit")
	parser.add_argument("-c", "--cookies", help="Cookies after authenticating to Salesforce application", default=None)
	parser.add_argument("-o", "--output-dir", help="Output directory", default=None)
	parser.add_argument("-l", "--object-list", help="Pull data of only the provided objects. Comma separated list of objects.", type=str, default=None)
	parser.add_argument("-d", "--debug", help="Print debug information", action="store_const", const=True, default=False)
	parser.add_argument("-v", "--verbose", help="Print verbose information", action="store_const", const=True, default=False)
	parser.add_argument("-p", "--proxy", help="Proxy requests", default=None)
	parser.add_argument("-k","--insecure", help="Ignore invalid TLS certificates", action="store_true")
	parser.add_argument("--app", help="Provide the target salesforce app's path (e.g: /myApp), the script will try to detect it if not provided")
	parser.add_argument("--aura", help="Provide the target salesforce aura's path (e.g: /aura), the script will try to detect it if not provided")
	parser.add_argument("--context", help="Provide a context to be used as aura.context in POST requests, the script will use a dummy one if not provided")
	parser.add_argument("--token", help="Provide an aura token to be used as aura.token in POST requests, the script will use a dummy one if not provided")
	parser.add_argument("--fetch-data", help="Fetch and save the actual records and metadata instead of just counting", action="store_true")
	parser.add_argument("--no-gql", help="Do not check for GraphQL capability and do not use it", action="store_true")
	parser.add_argument("--no-banner", help="Do not display banner", action="store_true")
	parser.add_argument("-r", "--aura-request-file", help="Provide a request file to an /aura endpoint")
	parser.add_argument("-x", "--experimental", help="Enable experimental extraction techniques (getRecord, getList, user enum, file downloads, controller probing, targeted GQL)", action="store_true")

	args = parser.parse_args()

	if len(sys.argv[1:]) == 0:
		parser.print_help()
		exit()

	add_logging_level('VERBOSE', 15)
	init_logger(logging.DEBUG if args.debug else logging.VERBOSE if args.verbose else logging.INFO)

	banner = r'''
    _                   ___                           _
   / \  _   _ _ __ __ _|_ _|_ __  ___ _ __   ___  ___| |_ ___  _ __
  / _ \| | | | '__/ _` || || '_ \/ __| '_ \ / _ \/ __| __/ _ \| '__|
 / ___ \ |_| | | | (_| || || | | \__ \ |_) |  __/ (__| || (_) | |
/_/   \_\__,_|_|  \__,_|___|_| |_|___/ .__/ \___|\___|\__\___/|_|
                                     |_|
	'''
	if not args.no_banner:
		logger.warning(banner)

	url = args.url	
	app = args.app
	cookies = args.cookies
	aura = args.aura
	token = args.token
	context = args.context

	if args.aura_request_file:
		parsed_http_req = parse_http_request_file(args.aura_request_file)
		
		url = parsed_http_req['url']
		aura = parsed_http_req['aura_endpoint']
		context = parsed_http_req['context']
		cookies = parsed_http_req['cookies']
		token = parsed_http_req['token']
	else:
		if url is None:
			logger.error('Specify a URL or a request file')
			exit()

		if url.endswith('/'):
			url = url[:-1] 

		if url.endswith('/s'):
			logger.warning('URL contains the /s path which is usually not the root, if this does not work try providing the URL without the /s')

	if app and app == "/":
		app = "/s"

	object_list = args.object_list
	if object_list:
		object_list = [str(obj) for obj in object_list.split(",")]

	audit(url, cookies=cookies,
		object_list=object_list,
		output_dir=args.output_dir,
		proxy=args.proxy,
		fetch_max_data=args.fetch_data,
		insecure=args.insecure,
		app=app,
		aura_path=aura,
		context=context,
		token=token,
		no_gql=args.no_gql,
		experimental=args.experimental
    )

if __name__ == "__main__":
    main()
