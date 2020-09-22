#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Leslie-Alexandre DENIS <git@eagleusb.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: consul_acl
short_description: Manipulate Consul Tokens and Policies (ACL)
description:
 - Allows to create, modify and remove Tokens and Policies
   See https://www.consul.io/docs/guides/acl.html.
version_added: "2.9"
author:
  - Leslie-Alexandre DENIS (@eagleusb)
options:
  mgmt_token:
    description:
      - admin token to manipulate tokens and policies.
  state:
    description:
      - add or remove the token and its policy
    required: false
    choices: ['present', 'absent']
    default: present
  name:
    description:
      - the name that should be associated with the token and its policy (alpha-numeric only)
    required: true
  token:
    description:
      - the wanted uuid for the token. If not set, consul will generate it
    required: false
  rules:
    type: list
    description:
      - rules definition associated to the given token through a policy
    required: false
  host:
    description:
      - host of the consul api, defaults to localhost
    required: false
    default: localhost
  port:
    type: int
    description:
      - port of the consul api, default to 8500
    required: false
    default: 8500
  scheme:
    description:
      - protocol scheme of the consul api, default http
    required: false
    default: http
  validate_certs:
    type: bool
    description:
      - whether to verify the tls certificate of the consul api
    required: false
    default: True
requirements:
  - python-consul2
  - pyhcl
  - requests
  - json
  - uuid
"""

EXAMPLES = """
- name: create a token with policy rules
  consul_acl:
    host: consul1.example.com
    mgmt_token: 123-456-789-123-456
    name: "foo-access"
    rules:
      key:
        "foo/bar":
            policy: "write"
- name: create a specific token with policy rules
  consul_acl:
    host: consul1.example.com
    mgmt_token: 123-456-789-123-456
    name: "foo-access"
    token: 456-456-789-123-456
    rules:
      key_prefix:
        "":
          policy: "read"
        "foo/private":
          policy: "deny"
      key:
        "foo/public":
          policy: "read"
        "foo/private":
          policy: "deny"
      node:
        "my-node":
          policy: "write"
- name: update the policy rules associated to a token
  consul_acl:
    host: consul1.example.com
    mgmt_token: 123-456-789-123-456
    name: "foo-access"
    token: 456-456-789-123-456
    rules:
      node:
        "my-node":
          policy: "write"
- name: remove a token
  consul_acl:
    host: consul1.example.com
    mgmt_token: 123-456-789-123-456
    token: 456-456-789-123-456
    state: absent
"""

RETURN = """
token:
    description: the token associated to the ACL (the ACL's ID)
    returned: success
    type: str
    sample: a2ec332f-04cf-6fba-e8b8-acf62444d3da
rules:
    description: the HCL JSON representation of the rules associated to the ACL, in the format described in the
                 Consul documentation (https://www.consul.io/docs/guides/acl.html#rule-specification).
    returned: I(status) == "present"
    type: str
    sample: {
        "key": {
            "foo": {
                "policy": "write"
            },
            "bar": {
                "policy": "deny"
            }
        }
    }
operation:
    description: the operation performed on the ACL
    returned: changed
    type: str
    sample: update
"""

try:
    import consul
    import hcl
    import json
    import uuid
    from requests.exceptions import ConnectionError
    from ansible.module_utils.basic import AnsibleModule
except ImportError:
    raise ImportError("You must install python-consul2, pyhcl and requests")

PARAM_DATACENTER = "datacenters"
PARAM_HOSTNAME = "host"
PARAM_NAME = "name"
PARAM_PORT = "port"
PARAM_RULES = "rules"
PARAM_SCHEME = "scheme"
PARAM_STATE = "state"
PARAM_TOKEN = "token"
PARAM_TOKEN_ADMIN = "mgmt_token"
PARAM_VALIDATE_CERTS = "validate_certs"

VALID_RULES_RESOURCE = [
    "agent",
    "agent_prefix",
    "event",
    "event_prefix",
    "key_prefix",
    "key",
    "keyring",
    "node",
    "node_prefix",
    "operator",
    "query",
    "query_prefix",
    "service",
    "service_prefix",
    "session",
    "session_prefix",
]
VALID_RULES_POLICY = [
    "read",
    "write",
    "deny",
    "list",
]

_ARGUMENT_SPEC = {
    PARAM_DATACENTER: dict(default=None, type="list"),
    PARAM_HOSTNAME: dict(default="localhost", type="str"),
    PARAM_NAME: dict(required=True, type="str"),
    PARAM_PORT: dict(default=8500, type="int"),
    PARAM_RULES: dict(default=None, required=False, type="dict"),
    PARAM_SCHEME: dict(required=False, default="http"),
    PARAM_STATE: dict(default="present", choices=["present", "absent"], type="list"),
    PARAM_TOKEN_ADMIN: dict(required=True, no_log=True, type="str"),
    PARAM_TOKEN: dict(required=False, no_log=True, type="str"),
    PARAM_VALIDATE_CERTS: dict(required=False, default=True, type="bool"),
}


class Consul(object):
    def __init__(self):
        self.result = {
            "changed": False,
            "message": "",
        }
        self.module = AnsibleModule(
            argument_spec=_ARGUMENT_SPEC,
            supports_check_mode=False,
            required_together=[],
        )
        self._consul_client()

    def _consul_client(self):
        token_admin = self.module.params[PARAM_TOKEN_ADMIN]
        if not token_admin:
            raise AssertionError(
                "Expecting the admin token to always be set")

        self.consul = consul.Consul(
            host=self.module.params[PARAM_HOSTNAME],
            port=self.module.params[PARAM_PORT],
            scheme=self.module.params[PARAM_SCHEME],
            verify=self.module.params[PARAM_VALIDATE_CERTS],
            token=token_admin,
            dc=None,
        )

    def _policy_exists(self):
        policy_exists = [
            True if policy["Name"] == self.module.params[PARAM_NAME] else False
            for policy in self.consul.acl.policy.list()
        ]
        return True in policy_exists

    def _policy_create(self):
        if self._policy_exists():
            self._policy_update()
        else:
            rules = self._json_from_yaml(self.module.params[PARAM_RULES])
            description = "Policy associated to {}".format(
                self.module.params[PARAM_NAME])
            datacenters = self.module.params[PARAM_DATACENTER]
            self.consul.acl.policy.create(
                name=self.module.params[PARAM_NAME],
                description=description,
                rules=rules,
                datacenters=datacenters,
            )
            self.result["message"] = "Policy created successfully."
            self.result["changed"] = True

    def _policy_update(self):
        policies = self.consul.acl.policy.list()
        for policy in policies:
            if policy["Name"] == self.module.params[PARAM_NAME]:
                current_policy = self.consul.acl.policy.get(
                    policy_id=policy["ID"])
                rules = self._json_from_yaml(self.module.params[PARAM_RULES])
                datacenters = self.module.params[PARAM_DATACENTER]
                # TODO: manage properly the case where datacenters need to be updated
                if current_policy["Rules"] != rules or "Datacenters" not in current_policy.keys():
                    self.consul.acl.policy.update(
                        policy_id=policy["ID"],
                        name=policy["Name"],
                        description=policy["Description"],
                        rules=rules,
                        datacenters=datacenters,
                    )
                    self.result["message"] = "Policy rules/datacenters updated successfully."
                    self.result["changed"] = True
                break

    def _policy_delete(self):
        policies = self.consul.acl.policy.list()
        for policy in policies:
            if policy["Name"] == self.module.params[PARAM_NAME]:
                self.consul.acl.policy.delete(policy_id=policy["ID"])
                self.result["message"] = "Policy deleted successfully."
                self.result["changed"] = True
                break

    def _token_exists(self, payload):
        predefined_accessor_id = payload["AccessorID"]
        token_exists = [
            True if token["AccessorID"] == predefined_accessor_id else False
            for token in self.consul.acl.tokens.list()
        ]
        return True in token_exists

    def _token_create(self):
        payload = {
            "AccessorID": str(uuid.uuid5(
                uuid.NAMESPACE_DNS, name=self.module.params[PARAM_NAME])),
            "Description": "Token for {}".format(self.module.params[PARAM_NAME]),
            "Policies": [
                {
                    "Name": self.module.params[PARAM_NAME]
                }
            ],
            "Local": False,
            # TODO: support temporary token
            # "ExpirationTime": "",
            # "ExpirationTTL": "",
        }
        secret_id = self.module.params[PARAM_TOKEN]
        if secret_id:
          payload["SecretID"] = secret_id

        if self._token_exists(payload):
            self._token_update(payload)
        else:
            self.consul.acl.tokens.create(payload)
            self.result["tokenid"] = payload["AccessorID"]
            self.result["message"] = "Token with associated Policy created successfully."
            self.result["changed"] = True

    def _token_update(self, payload):
        current_token = self.consul.acl.tokens.get(
            accessor_id=payload["AccessorID"])
        if not "Policies" in current_token.keys():
            self.consul.acl.tokens.update(
                accessor_id=payload["AccessorID"], payload=payload)
            self.result["tokenid"] = payload["AccessorID"]
            self.result["message"] = "Token association to Policy updated successfully."
            self.result["changed"] = True

    def _token_delete(self):
        accessor_id = str(uuid.uuid5(
            uuid.NAMESPACE_DNS, name=self.module.params[PARAM_NAME]))
        self.consul.acl.tokens.delete(accessor_id=accessor_id)
        self.result["message"] = "Token {} deleted successfully.".format(
            accessor_id)
        self.result["changed"] = True

    def _hcl_from_json(self, rules):
        try:
            rules_from_json = hcl.loads(rules)
            return rules_from_json
        except TypeError as identifier:
            pass

    def _json_from_yaml(self, rules):
        try:
            if not rules:
              rules = {}
            rules_from_yaml = json.dumps(rules)
            return rules_from_yaml
        except TypeError as identifier:
            pass

    def run(self):
        if self.module.params[PARAM_STATE] == ["present"]:
            # create associated policy
            self._policy_create()
            # create token with policy binding
            self._token_create()
        elif self.module.params[PARAM_STATE] == ["absent"]:
            # remove policy
            self._policy_delete()
            # remove token
            self._token_delete()
        self.module.exit_json(**self.result)


if __name__ == "__main__":
    Consul().run()
