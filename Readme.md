# B-Hunters-Nmap

This is the tool that is responsible to find open ports and services for B-Hunters project using NMAP.


## Requirements

To be able to use all the tools remember to update the environment variables with your API keys in `docker-compose.yml` file as some tools will not work well until you add the API keys.

## Usage 

To use this tool inside your B-Hunters Instance you can easily use docker compose file after editing `b-hunters.ini` with your configuration.
Also you can use it using the docker compose in the main repo of B-Hunters


## How it works

B-Hunters-Nmap receives the domain from the ui interface or the discord bot when the wildcard is activated for the scan
