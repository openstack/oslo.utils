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

import ast
import operator

import pyparsing


def _all_in(x, *y):
    x = ast.literal_eval(x)
    if not isinstance(x, list):
        raise TypeError("<all-in> must compare with a list literal"
                        " string, EG \"%s\"" % (['aes', 'mmx'],))
    return all(val in x for val in y)


def _range_in(x, *y):
    x = ast.literal_eval(x)
    if len(y) != 4:
        raise TypeError("<range-in> operator has to be followed by 2 "
                        "space separated numeric value surrounded by "
                        "brackets \"range_in [ 10 20 ] \"")
    num_x = float(x)
    num_y = float(y[1])
    num_z = float(y[2])
    if num_y > num_z:
        raise TypeError("<range-in> operator's first argument has to be "
                        "smaller or equal to the second argument EG"
                        "\"range_in  ( 10 20 ] \"")

    if y[0] == '[':
        lower = num_x >= num_y
    elif y[0] == '(':
        lower = num_x > num_y
    else:
        raise TypeError("The first element should be an opening bracket "
                        "(\"(\" or \"[\")")

    if y[3] == ']':
        upper = num_x <= num_z
    elif y[3] == ')':
        upper = num_x < num_z
    else:
        raise TypeError("The last element should be a closing bracket "
                        "(\")\" or \"]\")")
    return lower and upper


op_methods = {
    # This one is special/odd,
    # TODO(harlowja): fix it so that it's not greater than or
    # equal, see here for the original @ https://review.openstack.org/#/c/8089/
    '=': lambda x, y: float(x) >= float(y),
    # More sane ops/methods
    # Numerical methods
    '!=': lambda x, y: float(x) != float(y),
    '<=': lambda x, y: float(x) <= float(y),
    '<': lambda x, y: float(x) < float(y),
    '==': lambda x, y: float(x) == float(y),
    '>=': lambda x, y: float(x) >= float(y),
    '>': lambda x, y: float(x) > float(y),
    # String methods
    's!=': operator.ne,
    's<': operator.lt,
    's<=': operator.le,
    's==': operator.eq,
    's>': operator.gt,
    's>=': operator.ge,
    # Other
    '<all-in>': _all_in,
    '<in>': lambda x, y: y in x,
    '<or>': lambda x, *y: any(x == a for a in y),
    '<range-in>': _range_in,
}


def make_grammar():
    """Creates the grammar to be used by a spec matcher.

The grammar created supports the following operations.

Numerical values:
  * ``=  :`` equal to or greater than. This is equivalent to ``>=`` and is
    supported for `legacy reasons
    <http://docs.openstack.org/developer/nova/filter_scheduler.html#ComputeCapabilitiesFilter>`_
  * ``!= :`` Float/integer value not equal
  * ``<= :`` Float/integer value less than or equal
  * ``<  :`` Float/integer value less than
  * ``== :`` Float/integer value equal
  * ``>= :`` Float/integer value greater than or equal
  * ``>  :`` Float/integer value greater

String operations:
  * ``s!= :`` Not equal
  * ``s<  :`` Less than
  * ``s<= :`` Less than or equal
  * ``s== :`` Equal
  * ``s>  :`` Greater than
  * ``s>= :`` Greater than or equal

Other operations:
  * ``<all-in>  :`` All items 'in' value
  * ``<in>      :`` Item 'in' value, like a substring in a string.
  * ``<or>      :`` Logical 'or'
  * ``<range-in>:`` Range tester with customizable boundary conditions, tests
                    whether value is in the range, boundary condition could be
                    inclusve \'[\' or exclusive \'(\'.

If no operator is specified the default is ``s==`` (string equality comparison)

Example operations:
 * ``">= 60"`` Is the numerical value greater than or equal to 60
 * ``"<or> spam <or> eggs"`` Does the value contain ``spam`` or ``eggs``
 * ``"s== 2.1.0"`` Is the string value equal to ``2.1.0``
 * ``"<in> gcc"`` Is the string ``gcc`` contained in the value string
 * ``"<all-in> aes mmx"`` Are both ``aes`` and ``mmx`` in the value
 * ``"<range-in> [ 10 20 ]"`` float(value) >= 10 and float(value) <= 20
 * ``"<range-in> ( 10 20 ]"`` float(value) > 10 and float(value) <= 20
 * ``"<range-in> ( 10 20 )"`` float(value) > 10 and float(value) < 20

:returns: A pyparsing.MatchFirst object. See
          https://pythonhosted.org/pyparsing/ for details on pyparsing.
    """
    # This is apparently how pyparsing recommends to be used,
    # as http://pyparsing.wikispaces.com/share/view/644825 states that
    # it is not thread-safe to use a parser across threads.

    unary_ops = (
        # Order matters here (so that '=' doesn't match before '==')
        pyparsing.Literal("==") | pyparsing.Literal("=") |
        pyparsing.Literal("!=") | pyparsing.Literal("<in>") |
        pyparsing.Literal(">=") | pyparsing.Literal("<=") |
        pyparsing.Literal(">") | pyparsing.Literal("<") |
        pyparsing.Literal("s==") | pyparsing.Literal("s!=") |
        # Order matters here (so that '<' doesn't match before '<=')
        pyparsing.Literal("s<=") | pyparsing.Literal("s<") |
        # Order matters here (so that '>' doesn't match before '>=')
        pyparsing.Literal("s>=") | pyparsing.Literal("s>"))

    all_in_nary_op = pyparsing.Literal("<all-in>")
    or_ = pyparsing.Literal("<or>")
    range_in_binary_op = pyparsing.Literal("<range-in>")

    # An atom is anything not an keyword followed by anything but whitespace
    atom = ~(unary_ops | all_in_nary_op | or_ | range_in_binary_op) + \
        pyparsing.Regex(r"\S+")

    unary = unary_ops + atom
    range_op = range_in_binary_op + atom + atom + atom + atom
    nary = all_in_nary_op + pyparsing.OneOrMore(atom)
    disjunction = pyparsing.OneOrMore(or_ + atom)

    # Even-numbered tokens will be '<or>', so we drop them
    disjunction.setParseAction(lambda _s, _l, t: ["<or>"] + t[1::2])

    expr = disjunction | nary | range_op | unary | atom
    return expr


def match(cmp_value, spec):
    """Match a given value to a given spec DSL.

    This uses the grammar defined by make_grammar()

    :param cmp_value: Value to be checked for match.
    :param spec: The comparison specification string, for example ``">= 70"``
                 or ``"s== string_value"``. See ``make_grammar()`` for examples
                 of a specification string.
    :returns: True if cmp_value is a match for spec. False otherwise.
    """
    expr = make_grammar()
    try:
        # As of 2018-01-29 documentation on parseString()
        # https://pythonhosted.org/pyparsing/pyparsing.ParserElement-class.html#parseString
        #
        # parseString() will take our specification string, for example "< 6"
        # and convert it into a list of ['<', "6"]
        tree = expr.parseString(spec)
    except pyparsing.ParseException:
        # If an exception then we will just check if the value matches the spec
        tree = [spec]
    if len(tree) == 1:
        return tree[0] == cmp_value

    # tree[0] will contain a string representation of a comparison operation
    # such as '>=', we then convert that string to a comparison function
    compare_func = op_methods[tree[0]]
    return compare_func(cmp_value, *tree[1:])
