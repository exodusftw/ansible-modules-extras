#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2016, Jeremy Grant <jeremy.grant@outlook.com>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
---
module: validate
author: "Jeremy Grant (@exodusftw)"
version_added: 1.0
requirements: [ 're', 'yaml']
short_description: Methods for variable validation
description:
  - The M(validate) module provides a set of validation tools
    for variables. This is handled through a
    set of options to provide basic type enforcement,
    argument matching against a regular expression, integer range
    enforcement, and the ability to validate inputs
    against whitelist/blacklist entries.
options:
  blacklist:
    description:
      - List of user input values to reject
    required: false
    default: null
  delegate_to:
    description:
      - Host to execute validation tasks - defaults to ansible server
    required: true
    default: 127.0.0.1
  input_type:
    description:
      - Required data type for input value - if passed, module will fail
        if data type provided by user does not match input_type passed
        to validate
    required: false
    choices: [ I(boolean), I(bool), I(str), I(string), I(array), I(list), I(hash), I(dict), I(int) ]
    default: null
  matcher:
    description:
      - Regular expression to match against user input
        Expression should be passed as a string rather than I(/regex/)
    required: false
    default: null
  num_range:
    description:
      - Number Range to be used for validation
        against number vars - should be formatted as
        I(minimum-maximum) i.e. I(1-100)
    required: false
    default: null
  value:
    description:
      - User input variable to validate
    required: true
    default: null
  whitelist:
    description:
      - List of user input values to accept
    required: false
    default: null
'''

EXAMPLES = '''
# Basic input validation examples *assumes value field is user input var*

- name: validate boolean example with variable expansion
  validate:
  args:
    value: "{{ example_boolean_var }}"
    input_type: bool

- name: validate boolean stub variable
  validate:
  args:
    value: True
    input_type: bool

- name: validate stub integer variable range
  validate:
  args:
    value: 9
    num_range: '1-100'

- name: validate stub variable against regex
  validate:
  args:
    value: 'http://test.example.com/example/made-up-site'
    matcher: '^.*/example/.*$'

- name: validate stub variable against value whitelist
  validate:
  args:
    value: 'accepted_value1'
    whitelist:
      - 'accepted_value1'
      - 'accepted_value2'

- name: validate stub variable against value blacklist
  validate:
  args:
    value: 'rejected_value1'
    blacklist:
      - 'rejected_value1'
      - 'rejected_value2'
'''

RETURN = '''
---
pass:
  description: Returns a string containing the validation result
  returned: pass
  type: string
  sample: "PASS: Input value 'true' of type I(type bool) matches validation requirement for value to be of type: I(type bool)"
fail:
  description: Returns a string containing the validation result
  returned: fail
  type: string
  sample: "FAIL: Input value 'not_a_bool' of type I(type str) does not match validation requirement for value to be of type: I(type bool)"
'''

import re
import yaml

def main():
    module = AnsibleModule(
        argument_spec=dict(
            blacklist=dict(required=False, type='list'),
            delegate_to=dict(type='str', default='127.0.0.1'),
            input_type=dict(required=False, choices=[
                "bool",
                "boolean",
                "str",
                "string",
                "array",
                "list",
                "hash",
                "dict",
                "int"]),
            num_range=dict(required=False, type='str'),
            matcher=dict(required=False, type='str'),
            value=dict(required=True, default=None),
            whitelist=dict(required=False, type='list')
        )
    )

    params = module.params
    # Set the locale to C to ensure consistent messages.
    module.run_command_environ_update = dict(LANG='C', LC_ALL='C', LC_MESSAGES='C', LC_CTYPE='C')

    # Method for validating variable value meets specified data type
    def validate_input_type(value, input_type):

        # Map data types
        bool_types = ['bool', 'boolean']
        str_types = ['str', 'string']
        list_types = ['list', 'array']
        dict_types = ['dict', 'hash']
        num_types = ['int']

        # Determine Input value type
        if input_type in bool_types:
            real_type = bool
        elif input_type in str_types:
            real_type = str
        elif input_type in list_types:
            real_type = list
        elif input_type in dict_types:
            real_type = dict
        elif input_type in num_types:
            real_type = int

        # Determine actual data type from json object using yaml.safe_load
        json_value = json.dumps(value)
        real_value = yaml.safe_load(json.loads(json_value))
        # PASS if value data type matches specified data type - else FAIL
        # Message Formatting
        string_vars = {'value': value, 'value_type': type(real_value), 'real_type': real_type}
        if isinstance(real_value, real_type):
            pass_msg = ("PASS: Input value '{value}' of '{value_type}' "
                        "matches validation requirement for value to be of: '{real_type}")
            module.exit_json(changed=False, msg=pass_msg.format(**string_vars))
        else:
            fail_msg = ("FAIL: Input value '{value}' of: '{value_type}' does "
                        "not match validation requirement for value to be of: '{real_type}")
            module.fail_json(changed=False, msg=fail_msg.format(**string_vars))

    # Method for validating value against regular expression
    def validate_matcher(value, matcher, compiled_matcher):
        # Message Formatting
        string_vars = {'value': value, 'matcher': matcher}

        # PASS if value matches specificed regex - else FAIL
        if compiled_matcher.match(value):
            pass_msg = ("PASS: Input value '{value}' matches "
                        "validation requirement against regex: /{matcher}/")
            module.exit_json(changed=False, msg=pass_msg.format(**string_vars))
        else:
            fail_msg = ("FAIL: Input value '{value}' does not match "
                        "validation requirement against regex: /{matcher}/")
            module.fail_json(msg=fail_msg.format(**string_vars))

    # Method for validating number against specified number range
    def validate_num_range(value, range_min, range_max):
        int_value = int(value)
        # Message Formatting
        string_vars = {'value': value, 'range_min': range_min, 'range_max': range_max}

        # PASS if number within specified range - else FAIL
        if range_min <= int_value <= range_max:
            pass_msg = ("PASS: Input value '{value}' is within bounds of Number Range "
                        "{range_min}-{range_max} for validation requirement")
            module.exit_json(changed=False, msg=pass_msg.format(**string_vars))
        else:
            fail_msg = ("FAIL: Input value '{value}' is outside bounds of Number Range "
                        "{range_min}-{range_max} for validation requirement")
            module.fail_json(msg=fail_msg.format(**string_vars))

    # Method for validating values against specificed whitelist
    def validate_whitelist(value, whitelist):
        # Message Formatting
        string_vars = {'value': value, 'whitelist': whitelist}

        # PASS if value in Whitelist - else FAIL
        if value in whitelist:
            pass_msg = ("PASS: Input value '{value}' is contained within value "
                        "whitelist '{whitelist}' validation requirement")
            module.exit_json(changed=False, msg=pass_msg.format(**string_vars))
        else:
            fail_msg = ("FAIL: Input value '{value}' is not contained within value "
                       "whitelist '{whitelist}' validation requirement")
            module.fail_json(msg=fail_msg.format(**string_vars))

    # Method for validating values against specificed blacklist
    def validate_blacklist(value, blacklist):
        # Message Formatting
        string_vars = {'value': value, 'blacklist': blacklist}

        # PASS if value not in blacklist - else FAIL
        if value not in blacklist:
            pass_msg = ("PASS: Input value '{value}' is not contained within value "
                       "blacklist '{blacklist}' validation requirement")
            module.exit_json(changed=False, msg=pass_msg.format(**string_vars))
        else:
            fail_msg = ("FAIL: Input value '{value}' is contained within value "
                        "blacklist'{blacklist}' validation requirement")
            module.fail_json(msg=fail_msg.format(**string_vars))


    # Parse module args and invoke validation methods
    if params['value']:
        value = params['value']
    else:
        module.fail_json(msg="FAIL: value arg must be provided")

    if params['input_type']:
        input_type = params['input_type']
        validate_input_type(value, input_type)
    else:
        input_type = None

    if params['matcher']:
        matcher = params['matcher']
        compiled_matcher = re.compile(matcher)
        validate_matcher(value, matcher, compiled_matcher)
    else:
        matcher = None

    if params['num_range']:
        num_range = params['num_range'].split('-')
        range_min = int(num_range[0])
        range_max = int(num_range[1])
        validate_num_range(value, range_min, range_max)
    else:
        num_range = None

    if params['whitelist']:
        whitelist = params['whitelist']
        validate_whitelist(value, whitelist)
    else:
        whitelist = None

    if params['blacklist']:
        blacklist = params['blacklist']
        validate_blacklist(value, blacklist)
    else:
        blacklist = None


from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
