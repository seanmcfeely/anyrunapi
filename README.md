# AnyRunAPI

This library and CLI tool is for interfacing with the [ANY RUN Malware Hunting Service](https://any.run/) API.

I use this tool to programatically pull analysis artifacts/results for intel ingestion. The CLI interface is a convienience for manual investigations.

You can get an API key for the service [here](https://app.any.run/profile/).

## Install

`pip install anyrunapi`

## Library Use


```python3
from anyrunapi import AnyRunClient

apikey = "1Tl9yxVDEJPDqUzBQQkvxjusaNOFyZDaNftxapWT" # Fake
anyrun = AnyRunClient(apikey)

agent_tesla_task = "2f63c36f-e111-4ef4-b6da-ecb8655fc9c6"

# private access (have to own the task)
full_report = anyrun.get_report(agent_tesla_task)

# public access
report_summary = anyrun.get_report_summary(agent_tesla_task)

# public access
iocs = anyrun.get_report_iocs(agent_tesla_task)

# public access
result = anyrun.download_report_pcap(agent_tesla_task)
if result:
    print(f"{agent_tesla_task}.anyrun.pcap written to disk.")
```

## CLI tool

```
$ anyrun -h
usage: anyrun [-h] [-d] [-sh] [-e] [-u] {get,submit} ...

Any.Run API on the CLI

positional arguments:
  {get,submit}
    get                Get analysis report data by task ID.
    submit             Submit file for analysis.

optional arguments:
  -h, --help           show this help message and exit
  -d, --debug          Turn on debug logging.
  -sh, --show-history  Show analysis history.
  -e, --environments   Get AnyRun environments.
  -u, --user-limits    Get AnyRun user details.
```
