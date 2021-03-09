# Grafana Datasource Auth Proxy

Limit access to Grafana datasources per team.

## Table of Contents

- [About](#about)
  - [Project topic](#project-topic)
  - [Limitations](#limitations)
- [Usage](#usage)
  - [Installation](#installation)
  - [Configuration](#configuration)
- [Contribution](#contribution)
- [License](#license)

## About

### Project topic

When you're using Grafana datasource proxy feature (`Access: Server (default)` in datasource settings),
free version of Grafana does not implements any ACLs for that, and any user can query every datasource and
get metrics directly from it, even with `Viewer` rights.

Here is related [issue](https://github.com/grafana/grafana/issues/20843).

Grafana Enterprise although implements this [permissions](https://grafana.com/docs/grafana/latest/permissions/datasource_permissions/).

This project implements simple reverse proxy, that should be installed to handle `api/datasources/proxy`.

Here how it works:

- Check that requested path actually contains `api/datasources/proxy` to avoid proxying everything else;
- Check that there is `grafana_session` authentication cookie present;
- Get list of user's teams by authentication cookie;
- Check that at least on of the user's team have access to requested datasource;
- If everything is OK pass request to Grafana

### Limitations

Project is not production-ready and was build as an experiment. Use on your own risk.

Project supports only MySQL Grafana database backend (PR's welcome!)

Project was only tested againts Prometheus data sources

Project was only tested against Grafana 7

Project doest not supports non-standard Grafana auth cookie name (PR's welcome!)

## Usage

### Installation

There are multiple ways of installing `grafana-datasource-auth-proxy`.

#### Running from Helm chart

```bash
helm repo add grafana-datasource-auth-proxy https://dmitryshaburov.github.io/grafana-datasource-auth-proxy/
helm repo update
helm install [RELEASE_NAME] grafana-datasource-auth-proxy/grafana-datasource-auth-proxy
```

#### Running as Docker container

[dshaburov/grafana-datasource-auth-proxy](https://hub.docker.com/r/dshaburov/grafana-datasource-auth-proxy)

```bash
docker run -p 9608:9608 -v /etc/grafana-datasource-auth-proxy/config.yaml:/etc/grafana-datasource-auth-proxy/config.yaml dshaburov/grafana-datasource-auth-proxy:latest
```

#### Precompiled binaries

Precompiled binaries for released versions are available in the [Releases section](https://github.com/DmitryShaburov/grafana-datasource-auth-proxy/releases/).

#### Compiling the binary

You can checkout the source code and build manually:

```bash
git clone https://github.com/DmitryShaburov/grafana-datasource-auth-proxy.git
cd grafana-datasource-auth-proxy
go build .
./grafana-datasource-auth-proxy -config=config.yaml
```

### Configuration

#### Flags

Flag           |Environment Variable      | Default Value                                 |Description
-------------- |--------------------------|-----------------------------------------------|-----
config         |CONFIG\_FILE              |/etc/grafana-datasource-auth-proxy/config.yaml |"Path to configuration file")
listen-address |LISTEN\_ADDRESS           |:3000                                          |"The address to listen on for HTTP requests")
grafana-url    |GF\_SERVER\_DOMAIN        |grafana                                        |"Grafana remote origin host")
grafana-secret |GF\_SECURITY\_SECRET\_KEY |SW2YcwTIb9zpOOhoPsMm                           |Grafana encryption secret")
db-database    |GF\_DATABASE\_NAME        |grafana                                        |Grafana database name")
db-host        |GF\_DATABASE\_HOST        |127.0.0.1:3306                                 |Grafana database host and port")
db-user        |GF\_DATABASE\_USER        |                                               |Grafana database user")
db-pass        |GF\_DATABASE\_PASSWORD    |                                               |Grafana database password")
log-format     |LOG\_FORMAT               |txt                                            |Log format, valid options are txt and json
log-level      |LOG\_LEVEL                |info                                           |Log level, valid options are trace, debug, info, warn, error, fatal and panic

#### YAML config

See [config.yaml](https://github.com/DmitryShaburov/grafana-datasource-auth-proxy/blob/main/config.yaml)
for example configuration file.

#### Helm chart

See [values.yaml](https://github.com/DmitryShaburov/grafana-datasource-auth-proxy/blob/main/charts/grafana-datasource-auth-proxy/values.yaml)
for full list of available Helm chart values and their default configuration.

## Contribution

PRs on Feature Requests, Bug fixes are welcome. Feel free to open an issue and have a discussion first. Contributions on more alert scenarios, more metrics are also welcome and encouraged.

## License

[MIT](license)
