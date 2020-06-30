#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK

# QUICK AnyRun API lib and cli tool. Not complete.
#  https://any.run/api-documentation/

import os
import sys
import json
import logging
import argparse
import argcomplete
import coloredlogs
import requests
import configparser

# configure logging #
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - [%(levelname)s] %(message)s')

logger = logging.getLogger()
coloredlogs.install(level='INFO', logger=logger)

HOME_PATH = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATHS = [
    os.path.join(os.path.expanduser("~"),'.config', 'anyrun.ini'),
]

class AnyRun_Client():
    def __init__(self, api_key, host='api.any.run', verify_ssl=True):
        self.api_key = api_key
        self.host = host
        self.url_api_base = f"https://{host}/v1/"
        self.url_report_base = f"https://{host}/"
        self.url_content_base = f"https://content.any.run/"

    def _request(self, url, stream=True):
        logging.debug(f"making {url} request.")
        r = requests.get(url, headers={'Authorization': f"API-Key {self.api_key}"}, stream=stream)
        r.raise_for_status()
        return r

    def _api_request(self, resource, stream=True):
        url = self.url_api_base + resource
        return self._request(url)

    def _content_request(self, resource, stream=True):
        url = self.url_content_base + resource
        return self._request(url)

    def _report_request(self, resource, stream=True):
        url = self.url_report_base + resource
        return self._request(url)

    def get_environment(self):
        logging.debug("getting environment details.")
        r = self._api_request("environment")
        r.raise_for_status()
        return json.dumps(r.json(), indent=2, sort_keys=True)

    def get_user(self):
        logging.debug("getting user details.")
        r = self._api_request("user")
        r.raise_for_status()
        return json.dumps(r.json(), indent=2, sort_keys=True)

    def get_history(self, write_path=False):
        """Get analysis history for this account.
        """
        r = self._api_request("analysis")
        r.raise_for_status()
        return json.dumps(r.json(), indent=2, sort_keys=True)

    def get_report(self, task, write_path=False):
        """Get an analysis report by it's task id. return json unless write_path.
        """
        r = self._api_request(f"analysis/{task}")
        r.raise_for_status()
        if write_path:
            try:
                with open(write_path, 'w') as f:
                    f.write(json.dumps(r.json(), indent=2, sort_keys=True))
                if os.path.exists(write_path):
                    logging.info(f"Wrote {write_path}")
                    return True
                else:
                    return False
            except Exception as e:
                logging.error(f"{e} : r.text")
                return False
        return json.dumps(r.json(), indent=2, sort_keys=True)

    def get_report_iocs(self, task, write_path=False):
        logging.debug(f"Downloading IOCs for {task}")
        r = self._report_request(f"report/{task}/ioc/json")
        r.raise_for_status
        if write_path:
            try:
                with open(write_path, 'w') as f:
                    f.write(json.dumps(r.json(), indent=2, sort_keys=True))
                if os.path.exists(write_path):
                    logging.info(f"Wrote {write_path}")
                    return True
                else:
                    return False
            except Exception as e:
                logging.error(f"{e} : r.text")
                return False
        return json.dumps(r.json(), indent=2, sort_keys=True)

    def get_report_summary(self, task, write_path=False):
        logging.debug(f"Downloading IOCs for {task}")
        r = self._report_request(f"report/{task}/summary/json")
        r.raise_for_status
        if write_path:
            try:
                with open(write_path, 'w') as f:
                    f.write(json.dumps(r.json(), indent=2, sort_keys=True))
                if os.path.exists(write_path):
                    logging.info(f"Wrote {write_path}")
                    return True
                else:
                    return False
            except Exception as e:
                logging.error(f"{e} : r.text")
                return False
        return json.dumps(r.json(), indent=2, sort_keys=True)

    def download_report_pcap(self, task, write_path=None):
        logging.debug(f"downloading pcap for {task}")
        r = self._content_request(f"tasks/{task}/download/pcap")
        r.raise_for_status
        if not write_path:
            write_path = f"{task}.anyrun.pcap"
        try:
            with open(write_path, 'wb') as f:
                for chunk in r.iter_content(1024):
                    f.write(chunk)
            if os.path.exists(write_path):
                logging.info(f"Wrote {write_path}")
                return True
            else:
                return False
        except Exception as e:
            logging.error(f"{e}")
            print(r.text)
            return False


def main():

    parser = argparse.ArgumentParser(description="AnyRun API")
    parser.add_argument('-d', '--debug', action='store_true', help="turn on debug logging.")
    parser.add_argument('-sh', '--show-history', action='store_true', help="Show analysis history.")
    parser.add_argument('-e', '--environments', action='store_true', help="get AnyRun environments.")
    parser.add_argument('-u', '--user-limits', action='store_true', help="Get AnyRun user details.")
    subparsers = parser.add_subparsers(dest='command')
    get_parser = subparsers.add_parser('get', help="Get analysis report data by task ID.")
    get_parser.add_argument('task', action='store', help="An analysis task id.")
    get_parser.add_argument('-p', '--pcap', action='store_true', help="Download any pcap available for given report.")
    get_parser.add_argument('-i', '--ioc', action='store_true', help="download IOCs for report")
    get_parser.add_argument('-s', '--summary', action='store_true', help="get report summary")
    get_parser.add_argument('--json', action='store_true', help="if json results, return json.")

    submit_parser = subparsers.add_parser('submit', help="Submit file for analysis")
    submit_parser.add_argument('file', action='store', help="path to file to submit.")

    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    if args.debug:
        coloredlogs.install(level='DEBUG', logger=logger)
    
    config = configparser.ConfigParser()
    config.read(CONFIG_PATHS)

    host = config['default'].get('host')
    apikey = config['default'].get('api_key')

    anyrun = AnyRun_Client(apikey, host=host)

    if args.show_history:
        logging.info("getting history")
        print(anyrun.get_history())
        return True
    elif args.environments:
        logging.info("Getting environments.")
        print(anyrun.get_environment())
        return True
    elif args.user_limits:
        logging.info("getting user limits.")
        print(anyrun.get_user())
        return True
    elif args.command == 'get':
        if args.pcap:
            logging.info(f"Downloading pcap for {args.task}")
            r = anyrun.download_report_pcap(args.task)
            return r
        elif args.ioc:
            logging.info(f"Downloading IOCs for {args.task}")
            write_path=f"{args.task}.anyrun.ioc.json"
            if args.json:
                write_path=False
            r = anyrun.get_report_iocs(args.task, write_path=write_path)
            return r
        elif args.summary:
            logging.info(f"Downloading report summary for {args.task}")
            write_path=f"{args.task}.anyrun.summary.json"
            if args.json:
                write_path=False
            r = anyrun.get_report_summary(args.task, write_path=write_path)
            return r
        else:
            # by default, download the rull report
            logging.info(f"Getting analysis report for {args.task}")
            write_path=f"{args.task}.anyrun.ioc.json"
            if args.json:
                write_path=False
            r = anyrun.get_report(args.task, write_path=write_path)
            return r
    elif args.command == 'submit':
        logging.error("NOT YET IMPLEMENTED.")
        return True

    return True

if __name__ == '__main__':
    sys.exit(main())
