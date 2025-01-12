# Oxidized DNS server

This is a simple asynchronous DNS stub resolver that can:

- Act as a hosts file
- Block resolution of domains based on RegExp or domain names (including wildcard domains)

> Take a look at `denylist_sample` and `hosts_sample` for examples of how to add denylist/hosts entries

It supports:

- DNS-over-UDP
- DNS-over-TCP
- eDNS
- DNSSEC

It also has an optional API server that can be used to expose all kinds of DNS-related information, like the query log and statistics. It also can be used to modify the denylist and hosts file or to add new entries while the DNS server is running.

It also has a fairly simple Web UI written in React. You can find it in the `ui/` folder.

> This project was built mostly to learn how DNS works and to use it in my own homelab. Thus, bugs are kind of expected, as I am surely not a DNS expert :)

## Usage

```bash
Usage: o-dns [OPTIONS]

Options:
      --denylist-path <PATH>
      --allowlist-path <PATH>
      --max-parallel-connections <CONNECTIONS>  [default: 5]
      --host <ADDR>                             [default: 0.0.0.0]
  -p, --port <PORT>                             [default: 53]
      --upstream-resolver <ADDR>                [default: 1.1.1.1]
      --upstream-port <PORT>                    [default: 53]
      --config-path <PATH>
  -s, --disable-api-server
      --api-server-port <PORT>                  [default: 80]
  -h, --help                                    Print help
  -V, --version                                 Print version
```

## Running the server

You can run the server either by building it from the source or by using the provided Docker Compose file to run both the server and the UI.

### Building from source

```bash
git clone https://github.com/h33333333/o-dns
cargo build --release
```

### Running using Docker Compose

Ensure that the Docker daemon is running on your system and use the following command:

```bash
git clone https://github.com/h33333333/o-dns
docker compose up -d
```

This will run both the UI and the server. The DNS server will be available at `0.0.0.0:53`, while the UI can be found at `0.0.0.0:80`

> You can also customize the Docker Compose file so that it suits your needs.

## TODO

- Add allowlist support
- Increase test coverage
- Add proper CNAME support
- Allow loading denylists from URLs
- Improve caching logic
- Improve random color generation for query types and clients in the UI
- Add a way of grouping blocked domains and disabling these groups based on settings or on demand
