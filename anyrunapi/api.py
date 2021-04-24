# AnyRun API lib and cli tool.
# https://any.run/api-documentation/

import os
import json
import logging
import requests


class AnyRunClient:
    logger = logging.getLogger("anyrunapi.AnyRunClient")

    def __init__(self, api_key, host="api.any.run", verify_ssl=True):
        self.api_key = api_key
        self.host = host
        self.url_api_base = f"https://{host}/v1/"
        self.url_report_base = f"https://{host}/"
        self.url_content_base = f"https://content.any.run/"

    def _request(self, url, stream=True):
        logging.debug(f"making {url} request.")
        r = requests.get(url, headers={"Authorization": f"API-Key {self.api_key}"}, stream=stream)
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

    def get_history(self):
        """Get analysis history for this account."""
        r = self._api_request("analysis")
        r.raise_for_status()
        return json.dumps(r.json(), indent=2, sort_keys=True)

    def get_report(self, task, write_path=False):
        """Get an analysis report by it's task id. return json unless write_path."""
        r = self._api_request(f"analysis/{task}")
        r.raise_for_status()
        if write_path:
            try:
                with open(write_path, "w") as f:
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
                with open(write_path, "w") as f:
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
                with open(write_path, "w") as f:
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
            with open(write_path, "wb") as f:
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
