# CAN201 Network Labs

Two networking experiments from CAN201: a threaded STEP file-transfer client/server and OpenFlow 1.3 forwarding and redirection controllers.

## File transfer

Requires Python 3.10 or later. Install the client progress-bar dependency:

```sh
python -m pip install -r requirements.txt
```

Start the server in one terminal:

```sh
cd file-transfer
python server.py --ip 127.0.0.1 --port 1379
```

Upload a non-empty file from another terminal:

```sh
python file-transfer/client.py --server_ip 127.0.0.1 --port 1379 --id demo --f ./sample.bin --workers 4
```

Use `--compress` to upload a temporary gzip copy. The upload protocol sends a JSON header and binary blocks over TCP, transfers blocks across worker connections, and verifies the completed file with MD5. Uploaded files are stored under the server working directory's `file/<id>/` folder. File sizes are limited to 1 GiB. The server supports DATA operations and file download packets; the supplied client exposes uploading.

This is a local networking lab protocol: its username-derived MD5 login and plaintext TCP are not suitable for an Internet-facing storage service. A server-local random token secret is generated at startup; `STEP_TOKEN_SECRET` can set it explicitly for repeatable local testing. Restarting with a new secret invalidates existing tokens. Do not commit a real secret.

## SDN experiment

Run inside the course Linux lab/VM with Mininet, Open vSwitch, Ryu 4.34, and xterm installed. Ryu and Mininet depend on the VM's compatible Python and system packages; the pip file alone does not provision the VM.

Start one controller, then the topology in a second terminal:

```sh
ryu-manager --ofp-tcp-listen-port 6633 sdn/ryu_forward.py
sudo python3 sdn/networkTopo.py
```

For destination rewriting, stop that controller and launch `sdn/ryu_redirect.py` instead. Do not run both controllers against the same topology.

| Host | IP | Switch port |
| --- | --- | --- |
| server1 | 10.0.1.2 | 1 |
| server2 | 10.0.1.3 | 2 |
| client | 10.0.1.5 | 3 |

In the Mininet CLI, run `pingall`. Start TCP listeners on both server hosts in their xterms (for example `python3 -m http.server 8000`) and request `http://10.0.1.2:8000` from the client. The redirect controller rewrites the destination to server2 and rewrites replies to appear from server1. Inspect rules with `sh ovs-ofctl -O OpenFlow13 dump-flows s1`. Flow idle timeouts are five seconds.

## Tests

```sh
python -m unittest discover -s tests -v
```

Checks cover UTF-8 packet framing, fragmented packets, concurrent binary uploads and checksums, traversal rejection, malformed tokens, and incomplete-upload handling. Python syntax is checked for SDN files; live OpenFlow behavior requires the Linux lab environment.

## Contributors

Original CAN201 group: Kang Hu, Linhua Dong, Zhanhao Zhang, Haolun You, and Yifan Yang. Source scripts were retained and updated for packet handling, safe file components, upload completion tracking, and OpenFlow buffer handling. Original course reports remain in the local backup.
