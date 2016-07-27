# Copyright (c) 2011 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import operator

import pyparsing
from pyparsing import Literal
from pyparsing import OneOrMore
from pyparsing import Regex

op_methods = {
    # This one is special/odd,
    # TODO(harlowja): fix it so that it's not greater than or
    # equal, see here for the original @ https://review.openstack.org/#/c/8089/
    '=': lambda x, y: float(x) >= float(y),
    # More sane ops/methods
    '!=': lambda x, y: float(x) != float(y),
    '<=': lambda x, y: float(x) <= float(y),
    '<': lambda x, y: float(x) < float(y),
    '==': lambda x, y: float(x) == float(y),
    '>=': lambda x, y: float(x) >= float(y),
    '>': lambda x, y: float(x) > float(y),
    's!=': operator.ne,
    's<': operator.lt,
    's<=': operator.le,
    's==': operator.eq,
    's>': operator.gt,
    's>=': operator.ge,
    '<in>': lambda x, y: y in x,
    '<or>': lambda x, *y: any(x == a for a in y),
}


def make_grammar():
    """Creates the grammar to be used by a spec matcher."""
    # This is apparently how pyparsing recommends to be used,
    # as http://pyparsing.wikispaces.com/share/view/644825 states that
    # it is not thread-safe to use a parser across threads.

    unary_ops = (
        # Order matters here (so that '=' doesn't match before '==')
        Literal("==") | Literal("=") |
        Literal("!=") | Literal("<in>") |
        Literal(">=") | Literal("<=") |
        Literal(">") | Literal("<") |
        Literal("s==") | Literal("s!=") |
        # Order matters here (so that '<' doesn't match before '<=')
        Literal("s<=") | Literal("s<") |
        # Order matters here (so that '>' doesn't match before '>=')
        Literal("s>=") | Literal("s>"))

    or_ = Literal("<or>")

    # An atom is anything not an keyword followed by anything but whitespace
    atom = ~(unary_ops | or_) + Regex(r"\S+")

    unary = unary_ops + atom
    disjunction = OneOrMore(or_ + atom)

    # Even-numbered tokens will be '<or>', so we drop them
    disjunction.setParseAction(lambda _s, _l, t: ["<or>"] + t[1::2])

    expr = disjunction | unary | atom
    return expr


def match(cmp_value, spec):
    """Match a given value to a given spec DSL."""
    expr = make_grammar()
    try:
        ast = expr.parseString(spec)
    except pyparsing.ParseException:
        ast = [spec]
    if len(ast) == 1:
        return ast[0] == cmp_value
    op = op_methods[ast[0]]
    return op(cmp_value, *ast[1:])
