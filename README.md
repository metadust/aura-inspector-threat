# aura-inspector

This is a modified fork of the original Google/Mandiant aura-inspector, aimed at replicating the inadequate (mundane) TTPs used by ShinyHunters in their Salesforce data extortion campaigns. This tool is obviously not an officially supported Google product and is not eligible for the [Google Open Source Software Vulnerability Rewards Program](https://bughunters.google.com/open-source-security).


## Introduction

<b>aura-inspector</b> is a Swiss Army knife of Salesforce Experience Cloud testing. It facilitates in discovering misconfigured Salesforce Experience Cloud applications as well as automates much of the testing process. For more information, please refer to the Mandiant blog post: [Auditing Salesforce Aura Data Exposure](https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure).

Some of it's functionality includes:
- Discovery of accessible records from both Guest and Authenticated contexts
- Ability to get the total number of records of objects using undocumented GraphQL Aura method
- Checks for self-registration capabilities
- Facilitates in discovery of Record List components, providing UI access to list of misconfigured objects
- Discovery of "Home URLs", which could allow unauthorized access to sensitive administrative functionality

## What's different in this fork

The original Mandiant tool only counts objects and detects exposure, it doesn't actually extract anything useful. This fork does the full data grab.

### New flags

| Flag | Description |
|------|-------------|
| `--fetch-data` | Actually fetch and save the full records instead of just counting |
| `-x`, `--experimental` | Enable experimental extraction techniques (self-reg, file downloads, full detail, targeted GQL, etc.) |

### Experimental mode (`-x`)

Turns the tool into a full data extraction pipeline:

- **Self-registration** — Creates an account automatically, then re-audits with the authenticated session to pull more data
- **Full record detail** — Dumps every field via `getRecord` instead of just the list view columns
- **Targeted GraphQL** — Extracts Users (emails, usernames), Accounts, Contacts, ContentVersions (files), and KnowledgeArticles
- **File downloads** — Downloads actual file content from ContentVersion records
- **User enumeration** — Checks forgot-password and email-availability endpoints for user enumeration
- **Controller probing** — Probes additional Apex controllers for exposed actions
- **getList fallback** — Uses `getList` controller when `getItems` fails

### Data is saved to disk

Results get written to the output directory (`-o`):
- `records/` — Full JSON records per object
- `gql_records/` — GraphQL-fetched records
- `misc/` — Metadata, URLs, controllers, and experimental findings

If you don't specify `-o`, the script asks interactively whether to save.

### Full usage

```
python3 aura_cli.py -h
usage: python3 aura_cli.py [-h] [-u URL] [-c COOKIES] [-o OUTPUT_DIR] [-l OBJECT_LIST] [-d] [-v] [-p PROXY] [-k] [--app APP] [--aura AURA] [--context CONTEXT] [--token TOKEN] [--fetch-data] [--no-gql] [--no-banner] [-r AURA_REQUEST_FILE] [-x]

options:
  -h, --help                      show this help message and exit
  -u, --url URL                   Root URL of Salesforce application to audit
  -c, --cookies COOKIES           Cookies after authenticating to Salesforce application
  -o, --output-dir OUTPUT_DIR     Output directory
  -l, --object-list OBJECT_LIST   Pull records only the provided objects
  -d, --debug                     Print debug information
  -v, --verbose                   Print verbose information
  -p, --proxy PROXY               Proxy requests
  -k, --insecure                  Ignore invalid TLS certificates
  --app APP                       Target salesforce app path (e.g: /myApp)
  --aura AURA                     Aura endpoint path (e.g: /aura)
  --context CONTEXT               Aura context JSON
  --token TOKEN                   Aura token
  --fetch-data                    Fetch and save actual records instead of just counting
  --no-gql                        Skip GraphQL checks
  --no-banner                     Suppress the banner
  -r, --aura-request-file FILE    Request file to an /aura endpoint
  -x, --experimental              Enable experimental extraction (self-reg, file downloads, controller probing, targeted GQL, full detail)
```

### Examples

```
# Basic count check (guest)
python3 src/aura_cli.py -u https://example.force.com

# Full data extraction with experimental features
python3 src/aura_cli.py -u https://example.force.com -c "sid=abc123" --fetch-data -x -o results

# Authenticated from request file
python3 src/aura_cli.py -r request.txt --fetch-data -x -o results
```

## Installation

### pipx (Recommended)

The tool can be installed with pipx using the command below.
```
pipx install git+<URL>
```

### pip

The tool requires Python 3 to run and pip to download the dependencies. We recommend creating a virtual environment to install the dependencies.
```
git clone <URL>
cd aura-inspector
virtualenv env
source ./env/bin/activate
pip3 install -r requirements.txt
```

## Basic Usage

Using the tool in the standard configuration is as simple as running the following command. This will run all checks in an unauthenticated manner and return what is accessible from a Guest user perspective.

`python3 aura_cli.py -u <URL>`

The output will also reveal whether there is a self-registration functionality you can use to create an account. If you do have the opportunity to signup on the instance, running the tool from an authenticated context will likely yield more results. 

To run the tool in an authenticated context, either supply the SID cookie using the <b>-c</b> parameter or let the tool parse this and other parameters for you by supplying a file with the contents of an arbitrary request to the aura endpoint in an authenticated session. 

`python3 aura_cli.py -r <AURA_REQUEST_FILE>`

## Handling Multiple Apps

A single instance could have multiple custom apps hosted on it. This could typically be identified if you see something along the lines of `/<custom-app-name>/s` in the path. If this is the case, we recommend finding all apps, and specifying them using the `--app` parameter, as the output could differ significantly. It's also advised to try run the tool against the default app "/" if there are any custom apps hosted on the instance.

# Developed By:
- Amine Ismail
- Anirudha Kanodia


# Edited by:
- Metadust
