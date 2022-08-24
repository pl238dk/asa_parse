# Cisco ASA Firewall Configuration Parsing

This is a framework that is able to parse a Cisco ASA firewall configuration into a Python dictionary.

In one portion of the parsing, all object and object-groups are stored into a single dictionary `Config.object`.

In another portion of the parsing, all ACLs are stored in a single dictionary `Config.acl`.

## Getting Started

To instantiate a `Config` object :

```
>>> c = Config()
```

Pass in a filename, which resides in the same directory :

```
>>> filename = 'config.txt'
>>> c.load_config_from_file(filename)
```

Then call the `parse_config()` function :

```
>>> c.parse_config()
```

## Additional Features

A function `is_permit()` is capable of taking an input Source, Destination, and optional port (protocol/number format) and return whether or not the traffic is permitted.

The output of `is_permit()` will provide each ACL line where the input parameters' traffic is permitted.

This feature does not currently work with order-of-operations Deny statements. For example, a permit of 10.0.0.0/8 with a following rule of "Deny Any" will return a single output result.

Source and Destination inputs are passed as CIDR notation, otherwise a '/32' will be automatically appended.

Object-group, objects, service-group, and services are automatically translated from name to the underlying IPv4 values.

```
# Checks for internal network outbound toward Google's 8.8.8.8 on tcp/443 (https)
>>> source = '192.168.1.0/24'
>>> destination = '8.8.8.8'
>>> protocol_port = 'tcp/443'
>>> data = c.is_permit(source, destination, port=protocol_port)
```

Outputs (with object-groups automatically expanded) :

```
[
    {
        "name": "INSIDE_OUT",
        "raw": "acl INSIDE_OUT extended permit tcp object-group INTERNAL_NETWORKS object-group GOOGLE_8 eq 443 log",
        "src": [
            "192.168.1.0/24",
            "10.0.0.0/8",
            "172.16.0.0/16"
        ],
        "dst": ["8.8.8.8/32"],
        "action": "permit",
        "protocol": "tcp",
        "port": ["tcp/443"],
    },
]
```

If desired, the parsed configuration can be dumped to JSON by importing and executing JSON library functions :

```
>>> import json
>>> data = json.dumps(c.object, indent=2)
>>> with open('config_object.json', 'w') as f:
...     f.write(data)

>>>
```

## Worthy mentionables

The `tools.py` library has an amazing collection of simplified IP manipulation functions!
- IP to Binary
- IP to integer
- Binary to IP
- Binary to integer
- Integer to binary
- Integer to IP
- CIDR to binary
- CIDR to IP
- List all IPs in a range from start IP to end IP
- List all IPs in a CIDR range
- Find Most Significant Bits of a subnet
- Fill Most Significant Bits of a subnet with 1s or 0s
- Convert CIDR subnet to Python List
- Convert IP and subnet (e.g. "192.168.0.0 255.255.255.0") to CIDR notation
- List all subnets in a given supernet