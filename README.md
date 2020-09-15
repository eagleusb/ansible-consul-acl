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

| Name         | Required | Default Value | Description                                          |
|--------------|----------|---------------|------------------------------------------------------|
| skeleton_foo | no       | *5.0*         | flush input data to foobar every seconds.nanoseconds |

## Playbook Example

```yml
- hosts: all
  roles:
    - role: ansible-skeleton
      vars:
        skeleton_foo: "1.0"
```

## License

[GNU GENERAL PUBLIC LICENSE Version 3](./LICENSE)
