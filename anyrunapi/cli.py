import os
import json
import logging
import argparse
import coloredlogs
import configparser

from anyrunapi import AnyRunClient

LOGGER = logging.getLogger("anyrunapi.cli")

HOME_PATH = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATHS = [
    "/etc/anyrun/anyrun.ini",
    os.path.join(os.path.expanduser("~"), ".config", "anyrun.ini"),
]


def main():
    """Main interface for ANY.RUN"""

    # configure logging #
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - [%(levelname)s] %(message)s")
    coloredlogs.install(level="INFO", logger=logging.getLogger())

    parser = argparse.ArgumentParser(description="Any.Run API on the CLI")
    parser.add_argument("-d", "--debug", action="store_true", help="Turn on debug logging.")
    parser.add_argument("-sh", "--show-history", action="store_true", help="Show analysis history.")
    parser.add_argument("-e", "--environments", action="store_true", help="Get AnyRun environments.")
    parser.add_argument("-u", "--user-limits", action="store_true", help="Get AnyRun user details.")

    subparsers = parser.add_subparsers(dest="command")
    get_parser = subparsers.add_parser("get", help="Get analysis report data by task ID.")
    get_parser.add_argument("task", action="store", help="An analysis task id.")
    get_parser.add_argument("-p", "--pcap", action="store_true", help="Download any pcap available for given report.")
    get_parser.add_argument("-i", "--ioc", action="store_true", help="Download IOCs for report")
    get_parser.add_argument("-s", "--summary", action="store_true", help="Get report summary")
    get_parser.add_argument("--json", action="store_true", help="If json results, return json.")

    submit_parser = subparsers.add_parser("submit", help="Submit file for analysis.")
    submit_parser.add_argument("file", action="store", help="Path to file to submit.")

    args = parser.parse_args()

    if args.debug:
        coloredlogs.install(level="DEBUG", logger=logging.getLogger())

    config = configparser.ConfigParser()
    config.read(CONFIG_PATHS)

    host = config["default"].get("host")
    apikey = config["default"].get("api_key")

    anyrun = AnyRunClient(apikey, host=host)

    try:
        if args.show_history:
            LOGGER.info("getting history")
            print(anyrun.get_history())
            return True
        elif args.environments:
            LOGGER.info("Getting environments.")
            print(anyrun.get_environment())
            return True
        elif args.user_limits:
            LOGGER.info("getting user limits.")
            print(anyrun.get_user())
            return True
        elif args.command == "get":
            if args.pcap:
                LOGGER.info(f"Downloading pcap for {args.task}")
                r = anyrun.download_report_pcap(args.task)
                return r
            elif args.ioc:
                LOGGER.info(f"Downloading IOCs for {args.task}")
                write_path = f"{args.task}.anyrun.ioc.json"
                if args.json:
                    write_path = False
                r = anyrun.get_report_iocs(args.task, write_path=write_path)
                return r
            elif args.summary:
                LOGGER.info(f"Downloading report summary for {args.task}")
                write_path = f"{args.task}.anyrun.summary.json"
                if args.json:
                    write_path = False
                r = anyrun.get_report_summary(args.task, write_path=write_path)
                return r
            else:
                # by default, download the full report
                LOGGER.info(f"Getting analysis report for {args.task}")
                write_path = f"{args.task}.anyrun.json"
                if args.json:
                    write_path = False
                r = anyrun.get_report(args.task, write_path=write_path)
                return r
        elif args.command == "submit":
            raise NotImplementedError("Submit is not yet implemented. Use the ANY.RUN GUI.")
    except Exception as e:
        LOGGER.critical(e)

    return True
