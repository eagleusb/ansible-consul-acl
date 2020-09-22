# ansible-consul-acl

Manage Consul ACL and Tokens declaratively with Ansible.

![ansible-version](https://img.shields.io/badge/ansible-v2.9+-green.svg)
![last-commit](https://img.shields.io/github/last-commit/eagleusb/ansible-consul-acl)
![license](https://img.shields.io/github/license/eagleusb/ansible-consul-acl)

## Requirements

- python-consul2 = ">=0.1.4"
- requests = "*"
- pyhcl = ">=0.4.4"

## Quickstart

```sh
ansible-galaxy install eagleusb.consul_acl
```

## Variables

| Name                | Required | Default Value | Description                                      |
|---------------------|----------|---------------|--------------------------------------------------|
| consul_master_token | yes      | nil           | privileged master token to access consul api     |
| consul_server       | yes      | -             | consul server addr, port, scheme                 |
| consul_client_token | no       | []            | tokens(s) to add or update with associated rules |
| consul_remove_token | no       | []            | token(s) to remove from consul                   |

## Playbook Example

```yml
- name: "consul-acl"
  hosts: all
  roles:
    - role: "ansible-consul-acl"
      vars:
        consul_server:
          addr: "127.0.0.1"
          port: 8500
          scheme: "http"
        consul_master_token: "123-456-789"
        consul_client_token:
          - client: "foobar-todelete-later"
            token: "123-456-789"
          - client: "foobar-with-random-token"
          - client: "foobar-shuttle"
            token: "123-456-789"
            rules:
              event:
                "fiesta":
                    policy: write
              key:
                "foo/bar":
                  policy: read
                "foo/private":
                  policy: deny
              keyring: write
              node:
                "my-node":
                  policy: write
              operator: read
              query:
                "":
                  policy: write
              service:
                "consul":
                  policy: write
              session:
                "standup":
                  policy: write
        consul_remove_token:
          - client: "foobar-todelete-later"
```

## License

[GNU GENERAL PUBLIC LICENSE Version 3](./LICENSE)
