//--------------------------------------------------------------------------
// Copyright (C) 2021-2026 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// js_dealias_test.cc author Oleksandr Serhiienko <oserhiie@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "catch/catch.hpp"

#include "js_test_utils.h"

using namespace jsn;

// Unit tests

#ifdef CATCH_TEST_BUILD

TEST_CASE("De-aliasing - basic", "[JSNormalizer]")
{
    SECTION("alias entry cap triggers identifier overflow")
    {
        default_config.test_normalization(
            "a=eval;a=console;",
            "var_0000=eval;eval=console;",
            {identifier_depth(1), check_alias_limit_reached(true)}
        );
    }

    SECTION("function")
        test_normalization(
            "a = eval; a(\"2 + 2\");",
            "var_0000=eval;eval(\"2 + 2\");"
        );

    SECTION("composite")
        test_normalization(
            "a = console.log.execute; a(\"2 + 2\");",
            "var_0000=console.log.execute;console.log.execute(\"2 + 2\");"
        );

    SECTION("square bracket accessor")
        test_normalization(
            "a = console['log']; a(\"2 + 2\");",
            "var_0000=console['log'];console['log'](\"2 + 2\");"
        );

    SECTION("square bracket accessor - external script - end tag text")
        default_config.test_normalization(
            "a = console['</script x']; a;",
            "var_0000=console['</script x'];console['</script x'];",
            {normalize_as_external(true)}
        );

    SECTION("function call")
        test_normalization(
            "a = eval('console.log(\\\'foo\\\')'); a;",
            "var_0000=eval('console.log(\\\'foo\\\')');var_0000;"
        );

    SECTION("function call - composite")
        test_normalization(
            "a = console.log('123'); a;",
            "var_0000=console.log('123');var_0000;"
        );

    SECTION("function call - square bracket accessor")
        test_normalization(
            "a = console['log']('foo'); a;",
            "var_0000=console['log']('foo');var_0000;"
        );

    SECTION("function call - return value with dot accessor")
        test_normalization(
            "a = document.getElementById('id').field; a;",
            "var_0000=document.getElementById('id').field;var_0000;"
        );

    SECTION("function call - return value with square bracket accessor")
        test_normalization(
            "a = document.getElementById('id')['field']; a;",
            "var_0000=document.getElementById('id')['field'];var_0000;"
        );

    SECTION("with var keyword")
        test_normalization(
            "var a = eval; a('2 + 2');",
            "var var_0000=eval;eval('2 + 2');"
        );

    SECTION("with let keyword")
        test_normalization(
            "let a = eval; a('2 + 2');",
            "let var_0000=eval;eval('2 + 2');"
        );

    SECTION("with const keyword")
        test_normalization(
            "const a = eval; a('2 + 2');",
            "const var_0000=eval;eval('2 + 2');"
        );

    SECTION("with *=")
        test_normalization(
            "a *= eval; a;",
            "var_0000*=eval;var_0000;"
        );

    SECTION("with /=")
        test_normalization(
            "a /= eval; a;",
            "var_0000/=eval;var_0000;"
        );

    SECTION("with %=")
        test_normalization(
            "a %= eval; a;",
            "var_0000%=eval;var_0000;"
        );

    SECTION("with +=")
        test_normalization(
            "a += eval; a;",
            "var_0000+=eval;var_0000;"
        );

    SECTION("with -=")
        test_normalization(
            "a -= eval; a;",
            "var_0000-=eval;var_0000;"
        );

    SECTION("with <<=")
        test_normalization(
            "a <<= eval; a;",
            "var_0000<<=eval;var_0000;"
        );

    SECTION("with >>=")
        test_normalization(
            "a >>= eval; a;",
            "var_0000>>=eval;var_0000;"
        );

    SECTION("with >>>=")
        test_normalization(
            "a >>>= eval; a;",
            "var_0000>>>=eval;var_0000;"
        );

    SECTION("with &=")
        test_normalization(
            "a &= eval; a;",
            "var_0000&=eval;var_0000;"
        );

    SECTION("with ^=")
        test_normalization(
            "a ^= eval; a;",
            "var_0000^=eval;var_0000;"
        );

    SECTION("with |=")
        test_normalization(
            "a |= eval; a;",
            "var_0000|=eval;var_0000;"
        );

    SECTION("with prefix increment")
        test_normalization(
            "a = eval; a; ++a; a;",
            "var_0000=eval;eval;++eval;var_0000;"
        );

    SECTION("with prefix decrement")
        test_normalization(
            "a = eval; a; --a; a;",
            "var_0000=eval;eval;--eval;var_0000;"
        );

    SECTION("with postfix increment")
        test_normalization(
            "a = eval; a; a++; a;",
            "var_0000=eval;eval;eval++;var_0000;"
        );

    SECTION("with postfix decrement")
        test_normalization(
            "a = eval; a; a--; a;",
            "var_0000=eval;eval;eval--;var_0000;"
        );

    SECTION("with tilde")
        test_normalization(
            "a = eval; ~a; a;",
            "var_0000=eval;~eval;eval;"
        );

    SECTION("with exclamation sign")
        test_normalization(
            "a = eval; !a; a;",
            "var_0000=eval;!eval;eval;"
        );

    SECTION("with comparison operators")
        test_normalization(
            "a = eval;"
            "a >= a;"
            "a == a;"
            "a != a;"
            "a === a;"
            "a !== a;"
            "a < a;"
            "a > a;"
            "a <= a;",
            "var_0000=eval;"
            "eval>=eval;"
            "eval==eval;"
            "eval!=eval;"
            "eval===eval;"
            "eval!==eval;"
            "eval<eval;"
            "eval>eval;"
            "eval<=eval;"
        );

    SECTION("with binary operators")
        test_normalization(
            "a = eval;"
            "a & a;"
            "a | a;"
            "a ^ a;"
            "a >> a;"
            "a << a;",
            "var_0000=eval;"
            "eval&eval;"
            "eval|eval;"
            "eval^eval;"
            "eval>>eval;"
            "eval<<eval;"
        );

    SECTION("with logical operators")
        test_normalization(
            "a = eval;"
            "a && a;"
            "a || a;",
            "var_0000=eval;"
            "eval&&eval;"
            "eval||eval;"
        );

    SECTION("with ternary operator")
        test_normalization(
            "a = eval; b = true ? a : a; a; b;"
            "a = true ? a : a; a; b;",
            "var_0000=eval;var_0001=true?eval:eval;eval;var_0001;"
            "eval=true?var_0000:var_0000;var_0000;var_0001;"
        );

    SECTION("with single quotes string")
        test_normalization(
            "a = eval; a = 'str'; a;",
            "var_0000=eval;eval='str';var_0000;"
        );

    SECTION("with double quotes string")
        test_normalization(
            "a = eval; a = \"str\"; a;",
            "var_0000=eval;eval=\"str\";var_0000;"
        );

    SECTION("with regular expression")
        test_normalization(
            "a = eval; a = /regex/gs; a;",
            "var_0000=eval;eval=/regex/gs;var_0000;"
        );

    SECTION("with keyword")
        test_normalization(
            "a = eval; delete a; a;",
            "var_0000=eval;delete eval;eval;"
        );

    SECTION("within the parenthesis")
        test_normalization(
            "a = eval; (a);",
            "var_0000=eval;(eval);"
        );

    SECTION("within the square brackets")
        test_normalization(
            "a = eval; b[a];",
            "var_0000=eval;var_0001[eval];"
        );

    SECTION("redefinition")
        test_normalization(
            "a = eval; var a; let a; const a; a;",
            "var_0000=eval;var eval;let eval;const eval;eval;"
        );

    SECTION("operand - lhs")
        test_normalization(
            "a = eval; a + 2; a;",
            "var_0000=eval;eval+2;eval;"
        );

    SECTION("operand - rhs")
        test_normalization(
            "a = eval; 2 - a; a;",
            "var_0000=eval;2-eval;eval;"
        );

    SECTION("assignment with modification")
        test_normalization(
            "var a = eval + b++; a;",
            "var var_0000=eval+var_0001++;var_0000;"
        );

    SECTION("simple reassignment")
        test_normalization(
            "a = eval; a = 2; a;",
            "var_0000=eval;eval=2;var_0000;"
        );

    SECTION("self reassignment")
        test_normalization(
            "a = eval; a = a; a;",
            "var_0000=eval;eval=eval;eval;"
        );

    SECTION("self reassignment with modification")
        test_normalization(
            "a = eval; a += a; a;",
            "var_0000=eval;eval+=var_0000;var_0000;"
        );

    SECTION("indirect reassignment")
        test_normalization(
            "a = eval; b = a; a = b; a();b();",
            "var_0000=eval;var_0001=eval;eval=eval;eval();eval();"
        );

    SECTION("direct reassignment")
        test_normalization(
            "a = eval; a = console.log; a();",
            "var_0000=eval;eval=console.log;console.log();"
        );

    SECTION("reassignment with modification")
        test_normalization(
            "a = eval; a += 2; a;",
            "var_0000=eval;eval+=2;var_0000;"
        );

    SECTION("reassignment with operation")
        test_normalization(
            "a = eval; a = a % 2; a;",
            "var_0000=eval;eval=eval%2;var_0000;"
        );

    SECTION("reassignment with modification and operation")
        test_normalization(
            "a = eval; a %= 2 * a; b = eval; b = 2 / a; a; b;",
            "var_0000=eval;eval%=2*var_0000;var_0001=eval;eval=2/var_0000;var_0000;var_0001;"
        );

    SECTION("reassignment with prefix increment")
        test_normalization(
            "a = eval; a; b = ++a; a; b;",
            "var_0000=eval;eval;var_0001=++eval;var_0000;var_0001;"
        );

    SECTION("reassignment with prefix decrement")
        test_normalization(
            "a = eval; a; b = --a; a; b;",
            "var_0000=eval;eval;var_0001=--eval;var_0000;var_0001;"
        );

    SECTION("reassignment with postfix increment")
        test_normalization(
            "a = eval; a; b = a++; a; b;",
            "var_0000=eval;eval;var_0001=eval++;var_0000;var_0001;"
        );

    SECTION("reassignment with postfix decrement")
        test_normalization(
            "a = eval; a; b = a--; a; b;",
            "var_0000=eval;eval;var_0001=eval--;var_0000;var_0001;"
        );

    SECTION("reassignment with postfix decrement and operation")
        test_normalization(
            "a = eval; a; b = a-- + 2; a; b;",
            "var_0000=eval;eval;var_0001=eval-- +2;var_0000;var_0001;"
        );

    SECTION("reassignment with postfix decrement and modification")
        test_normalization(
            "a = eval; a; b /= a--; a; b;",
            "var_0000=eval;eval;var_0001/=eval--;var_0000;var_0001;"
        );

    SECTION("compound identifiers - dot accessor")
        test_normalization(
            "a = eval; foo.a; a; a.bar = 2; a;",
            "var_0000=eval;var_0001.var_0000;eval;eval.bar=2;eval;"
        );

    SECTION("compound identifiers - square bracket accessor")
        test_normalization(
            "a = eval; foo['a']; a; a['bar'];",
            "var_0000=eval;var_0001['a'];eval;eval['bar'];"
        );

    SECTION("multiple declaration")
        test_normalization(
            "var a, b = eval, c = eval; a; b; c;",
            "var var_0000,var_0001=eval,var_0002=eval;var_0000;eval;eval;"
        );

    SECTION("with automatic semicolon insertion")
        test_normalization(
            "a \n = \n eval \n a \n eval;",
            "var_0000=eval;eval;eval;"
        );

    SECTION("with unescape")
        test_normalization(
            "a = \\u0065\\u{0076}\\u0061\\u{006C}; a(); a.foo();",
            "var_0000=eval;eval();eval.foo();"
        );

    SECTION("dealias_identifier exact boundary initial assignment")
    {
        test_normalization(
            "a = console.name; b = a.a; b;",
            "var_0000=console.name;var_0001=console.name.a;console.name.a;",
            {max_dealias_buf_size(14)}
        );
    }

    SECTION("dealias_identifier exact boundary with space-separated identifiers")
    {
        test_normalization(
            "a = eval; b = a a; b;",
            "var_0000=eval;var_0001=eval eval;evaleval;",
            {max_dealias_buf_size(8)}
        );
    }

    SECTION("dealias_append exact boundary with bracket accessor")
    {
        test_normalization(
            "a = console['ab']; a;",
            "var_0000=console['ab'];console['ab'];",
            {max_dealias_buf_size(13)}
        );
    }

    SECTION("dealias_identifier resets alias tracking")
    {
        test_normalization(
            "a = console.name; b = a.a; b;",
            "var_0000=console.name;var_0001=console.name.a;var_0001;",
            {max_dealias_buf_size(13)}
        );
    }

    SECTION("dealias_identifier resets alias with space-separated identifiers")
    {
        test_normalization(
            "a = eval; b = a a; b;",
            "var_0000=eval;var_0001=eval eval;var_0001;",
            {max_dealias_buf_size(7)}
        );
    }

    SECTION("dealias_append resets alias tracking")
    {
        test_normalization(
            "a = console.name; b = a.a; b;",
            "var_0000=console.name;var_0001=console.name.a;var_0001;",
            {max_dealias_buf_size(12)}
        );
    }

    SECTION("dealias_append resets with bracket accessor string")
    {
        test_normalization(
            "a = console['abcd']; a;",
            "var_0000=console['abcd'];var_0000;",
            {max_dealias_buf_size(10)}
        );
    }

    SECTION("multiple aliases both within cap")
    {
        test_normalization(
            "a = eval; b = console; a; b;",
            "var_0000=eval;var_0001=console;eval;console;",
            {max_dealias_buf_size(7)}
        );
    }

    SECTION("first alias overflows cap, second alias fits")
    {
        test_normalization(
            "a = console.name; b = eval; a; b;",
            "var_0000=console.name;var_0001=eval;var_0000;eval;",
            {max_dealias_buf_size(11)}
        );
    }

    SECTION("first alias fits cap, second alias overflows")
    {
        test_normalization(
            "a = eval; b = console.name; a; b;",
            "var_0000=eval;var_0001=console.name;eval;var_0001;",
            {max_dealias_buf_size(11)}
        );
    }

    SECTION("chained alias overflows cap without affecting first alias")
    {
        test_normalization(
            "a = console; b = a.name; a; b;",
            "var_0000=console;var_0001=console.name;console;var_0001;",
            {max_dealias_buf_size(10)}
        );
    }
}

TEST_CASE("De-aliasing - split", "[JSNormalizer]")
{
    SECTION("var keyword")
        test_normalization({
            {"v", "var_0000"},
            {"ar a = eval; a;", "var var_0001=eval;eval;"}
        });

    SECTION("let keyword")
        test_normalization({
            {"l", "var_0000"},
            {"et a = eval; a;", "let var_0001=eval;eval;"}
        });

    SECTION("const keyword")
        test_normalization({
            {"cons", "var_0000"},
            {"t a = eval; a;", "const var_0001=eval;eval;"}
        });

    SECTION("alias name")
        test_normalization({
            {"var alias_", "var var_0000"},
            {"name = eval; alias_name;", "var var_0001=eval;eval;"}
        });

    SECTION("fake alias name")
        test_normalization({
            {"a = eval; b = a", "var_0000=eval;var_0001=eval"},
            {"b; b;", "var_0000=eval;var_0001=var_0002;var_0001;"}
        });

    SECTION("alias value")
        test_normalization({
            {"a = e", "var_0000=var_0001"},
            {"val; a;", "var_0000=eval;var_0000;"}
        });

    SECTION("before assignment")
        test_normalization({
            {"a ", "var_0000"},
            {"= eval; a;", "var_0000=eval;eval;"}
        });

    SECTION("after assignment")
        test_normalization({
            {"a =", "var_0000="},
            {" eval; a;", "var_0000=eval;eval;"}
        });

    SECTION("assignment with modification")
        test_normalization({
            {"a *", "var_0000*"},
            {"= eval; a;", "var_0000*=eval;var_0000;"}
        });

    SECTION("alias value as a function")
        test_normalization({
            {"a = e", "var_0000=var_0001"},
            {"val; a;", "var_0000=eval;var_0000;"}
        });

    SECTION("composite alias value with dot accessor")
        test_normalization({
            {"a = console.", "var_0000=console."},
            {"log; a();", "var_0000=console.log;console.log();"}
        });

    SECTION("composite alias value with square bracket accessor")
        test_normalization({
            {"a = console[", "var_0000=console["},
            {"'log']; a();", "var_0000=console['log'];console['log']();"}
        });

    SECTION("function call")
        test_normalization({
            {"a = eval", "var_0000=eval"},
            {"(); a;", "var_0000=eval();var_0000;"}
        });

    SECTION("function call - dot accessor")
        test_normalization({
            {"a = console.", "var_0000=console."},
            {"log(); a;", "var_0000=console.log();var_0000;"}
        });

    SECTION("function call - square bracket accessor")
        test_normalization({
            {"a = console[", "var_0000=console["},
            {"'log'](); a;", "var_0000=console['log']();var_0000;"}
        });

    SECTION("prefix increment")
        test_normalization({
            {"a = eval; +", "var_0000=eval;+"},
            {"+a; a;", "var_0000=eval;++eval;var_0000;"}
        });

    SECTION("postfix increment")
        test_normalization({
            {"a = eval; a+", "var_0000=eval;eval+"},
            {"+; a;", "var_0000=eval;eval++;var_0000;"}
        });

    SECTION("prefix decrement")
        test_normalization({
            {"a = eval; -", "var_0000=eval;-"},
            {"-a; a;", "var_0000=eval;--eval;var_0000;"}
        });

    SECTION("postfix decrement")
        test_normalization({
            {"a = eval; a-", "var_0000=eval;eval-"},
            {"-; a;", "var_0000=eval;eval--;var_0000;"}
        });

    SECTION("before operator")
        test_normalization({
            {"a = eval; a", "var_0000=eval;eval"},
            {" + a; a;", "var_0000=eval;eval+eval;eval;"}
        });

    SECTION("after operator")
        test_normalization({
            {"a = eval; a +", "var_0000=eval;eval+"},
            {" a; a;", "var_0000=eval;eval+eval;eval;"}
        });

    SECTION("comparison operator")
        test_normalization({
            {"a = eval; a =", "var_0000=eval;eval="},
            {"= a; a;", "var_0000=eval;eval==eval;eval;"}
        });

    SECTION("logical operator")
        test_normalization({
            {"a = eval; a |", "var_0000=eval;eval|"},
            {"| a; a;", "var_0000=eval;eval||eval;eval;"}
        });

    SECTION("before binary operator")
        test_normalization({
            {"a = eval; a ", "var_0000=eval;eval"},
            {"| a; a;", "var_0000=eval;eval|eval;eval;"}
        });

    SECTION("after binary operator")
        test_normalization({
            {"a = eval; a |", "var_0000=eval;eval|"},
            {" a; a;", "var_0000=eval;eval|eval;eval;"}
        });

    SECTION("shift operator")
        test_normalization({
            {"a = eval; a <", "var_0000=eval;eval<"},
            {"< a; a;", "var_0000=eval;eval<<eval;eval;"}
        });

    SECTION("single quotes string")
        test_normalization({
            {"a = eval; a = ' ", "var_0000=eval;eval=' "},
            {" '; a;", "var_0000=eval;eval='  ';var_0000;"}
        });

    SECTION("double quotes string")
        test_normalization({
            {"a = eval; a = \" ", "var_0000=eval;eval=\" "},
            {" \"; a;", "var_0000=eval;eval=\"  \";var_0000;"}
        });

    SECTION("regex")
        test_normalization({
            {"a = eval; a = / ", "var_0000=eval;eval=/ "},
            {" /g; a;", "var_0000=eval;eval=/  /g;var_0000;"}
        });

    SECTION("keyword")
        test_normalization({
            {"a = eval; type", "var_0000=eval;var_0001"},
            {"of a; a;", "var_0000=eval;typeof eval;eval;"}
        });

    SECTION("assignment with modification")
        test_normalization({
            {"var a = eval", "var var_0000=eval"},
            {" + b++; a;", "var var_0000=eval+var_0001++;var_0000;"}
        });

    SECTION("before reassignment")
        test_normalization({
            {"a = eval; a ", "var_0000=eval;eval"},
            {" = b; a;", "var_0000=eval;eval=var_0001;var_0000;"}
        });

    SECTION("after reassignment")
        test_normalization({
            {"a = eval; a =", "var_0000=eval;eval="},
            {" b; a;", "var_0000=eval;eval=var_0001;var_0000;"}
        });

    SECTION("before self reassignment")
        test_normalization({
            {"a = eval; a ", "var_0000=eval;eval"},
            {" = a; a;", "var_0000=eval;eval=eval;eval;"}
        });

    SECTION("after self reassignment")
        test_normalization({
            {"a = eval; a =", "var_0000=eval;eval="},
            {" a; a;", "var_0000=eval;eval=eval;eval;"}
        });

    SECTION("self reassignment with modification")
        test_normalization({
            {"a = eval; a +", "var_0000=eval;eval+"},
            {"= a; a;", "var_0000=eval;eval+=var_0000;var_0000;"}
        });

    SECTION("reassignment with operation")
        test_normalization({
            {"a = eval; a = a +", "var_0000=eval;eval=eval+"},
            {" 2; a;", "var_0000=eval;eval=eval+2;var_0000;"}
        });

    SECTION("automatic semicolon insertion")
        test_normalization({
            {"a \n = \n", "var_0000="},
            {"eval \n a;", "var_0000=eval;eval;"}
        });

    SECTION("compound identifiers - dot accessor")
        test_normalization({
            {"a = eval; foo.", "var_0000=eval;var_0001."},
            {"a; a; a.", "var_0000=eval;var_0001.var_0000;eval;eval."},
            {"bar = 2; a;", "var_0000=eval;var_0001.var_0000;eval;eval.bar=2;eval;"}
        });

    SECTION("compound identifiers - square bracket accessor")
        test_normalization({
            {"a = eval; foo[", "var_0000=eval;var_0001["},
            {"'a']; a; a[", "var_0000=eval;var_0001['a'];eval;eval["},
            {"'bar']; a;", "var_0000=eval;var_0001['a'];eval;eval['bar'];eval;"}
        });
}

TEST_CASE("De-aliasing - scopes", "[JSNormalizer]")
{
    SECTION("lookup through function")
        test_normalization(
            "a = eval; function f() { a; }",
            "var_0000=eval;function var_0001(){eval;}"
        );

    SECTION("lookup through statement block")
        test_normalization(
            "a = eval; if (true) { a; }",
            "var_0000=eval;if(true){eval;}"
        );

    SECTION("lookup through object")
        test_normalization(
            "a = eval; obj = {b : a}",
            "var_0000=eval;var_0001={var_0002:eval}"
        );

    SECTION("lookup through code block")
        test_normalization(
            "a = eval; { a; }",
            "var_0000=eval;{eval;}"
        );

    SECTION("assignment in function")
        test_normalization(
            "function f() { a = eval; a; } a;",
            "function var_0000(){var_0001=eval;eval;}var_0001;"
        );

    SECTION("assignment in statement block")
        test_normalization(
            "if (true) { a = eval; a; } a;",
            "if(true){var_0000=eval;eval;}var_0000;"
        );

    SECTION("assignment in object")
        test_normalization(
            "obj = { a : eval, b : a } a;",
            "var_0000={var_0001:eval,var_0002:var_0001}var_0001;"
        );

    SECTION("assignment in code block")
        test_normalization(
            "{ a = eval; a; } a;",
            "{var_0000=eval;eval;}var_0000;"
        );

    SECTION("reassignment in function")
        test_normalization(
            "a = eval; function f(){ a = console.log; a; a = 2; } a;",
            "var_0000=eval;function var_0001(){eval=console.log;console.log;console.log=2;}eval;"
        );

    SECTION("reassignment in statement block")
        test_normalization(
            "a = eval; if (true) { a = console.log; a; a = 2; } a;",
            "var_0000=eval;if(true){eval=console.log;console.log;console.log=2;}eval;"
        );

    SECTION("reassignment in object")
        test_normalization(
            "a = eval; obj = { a : console.log, b : a, a : 2 } a;",
            "var_0000=eval;var_0001={eval:console.log,var_0002:eval,eval:2}eval;"
        );

    SECTION("reassignment in code block")
        test_normalization(
            "a = eval; { a = console.log; a; a = 2; } a;",
            "var_0000=eval;{eval=console.log;console.log;console.log=2;}eval;"
        );

    SECTION("function argument")
        test_normalization(
            "a = eval; function f(a) { a; a = console.log; a; } f(a);",
            "var_0000=eval;function var_0001(eval){eval;eval=console.log;console.log;}"
            "var_0001(eval);"
        );

    SECTION("statement block argument")
        test_normalization(
            "a = eval; b = console.log; for ( let a, b; ; ) { a; b; } a; b;",
            "var_0000=eval;var_0001=console.log;for(let eval,console.log;;){eval;console.log;}"
            "eval;console.log;"
        );

    SECTION("single line statement block - lookup")
        test_normalization(
            "a = eval; if (true) a; a;",
            "var_0000=eval;if(true)eval;eval;"
        );

    SECTION("single line statement block - reassignment")
        test_normalization(
            "a = eval; if (true) a = console.log; a;",
            "var_0000=eval;if(true)eval=console.log;eval;"
        );

    SECTION("arrow function")
        test_normalization(
            "a = eval; b = (a) => {a; a = console.log; a;}; a;",
            "var_0000=eval;var_0001=(eval)=>{eval;eval=console.log;console.log;};eval;"
            // corner case
        );

    SECTION("default function argument")
        test_normalization(
            "a = eval; function f(a = 2) { a; } a;",
            "var_0000=eval;function var_0001(eval=2){var_0000;}eval;"
        );

    SECTION("default arrow function argument")
        test_normalization(
            "a = eval; b = (a = 2) => { a; }; a;",
            "var_0000=eval;var_0001=(eval=2)=>{var_0000;};var_0000;"
            // corner case
        );

    SECTION("multiple nesting")
        test_normalization(
            "a = eval; function f() { a; a = console.log; a; "
            "if (true) { a; a = document; a; } a; } a;",
            "var_0000=eval;function var_0001(){eval;eval=console.log;console.log;"
            "if(true){console.log;console.log=document;document;}console.log;}eval;"
        );

    SECTION("automatic semicolon insertion")
        test_normalization(
            "a = eval; if (true)\na\n=\nconsole\n.log\n\n a;",
            "var_0000=eval;if(true)eval=console.log;eval;"
        );
}

TEST_CASE("De-aliasing - class", "[JSNormalizer]")
{

    SECTION("basic case")
        test_normalization(
            "a = new String(); a.foo()",
            "var_0000=new String();var_0000.foo()"
        );

    SECTION("unknown class")
        test_normalization(
            "a = new foo(); a.bar()",
            "var_0000=new var_0001();var_0000.var_0002()"
        );

    SECTION("complex parameters")
        test_normalization(
            "a = new String(10,p+q,eval('f')); a.foo()",
            "var_0000=new String(10,var_0001+var_0002,eval('f'));var_0000.foo()"
        );

    SECTION("accessor chain")
        test_normalization(
            "a = new String.foo(); a.bar()",
            "var_0000=new String.foo();var_0000.bar()"
        );

    SECTION("square bracket accessor")
        test_normalization(
            "a = new String['foo'](); a.bar()",
            "var_0000=new String['foo']();var_0000.bar()"
        );

    SECTION("property of a constructed object")
        test_normalization(
            "a = new String().length; a.bar()",
            "var_0000=new String().length;var_0000.bar()"
        );

    SECTION("de-alias chaining")
        test_normalization(
            "s = String; a = new s(); a.baz()",
            "var_0000=String;var_0001=new String();var_0001.baz()"
        );

    SECTION("single-line comment after new")
        test_normalization(
            "o = new //split\n String(); o.foo()",
            "var_0000=new String();var_0000.foo()"
        );

    SECTION("multi-line comment after new")
        test_normalization(
            "o = new /*split*/ String(); o.foo()",
            "var_0000=new String();var_0000.foo()"
        );

    SECTION("semicolon after new")
        test_normalization(
            "o = new; String(); o.foo()",
            "var_0000=new;String();var_0000.var_0001()"
        );
}

TEST_CASE("De-aliasing - binding patterns", "[JSNormalizer]")
{
    SECTION("simple declaration")
        test_normalization(
            "var a = unescape; a('%41');",
            "var var_0000=unescape;'A';"
        );

    SECTION("array pattern")
        test_normalization(
            "var [a] = [unescape]; a('%41');",
            "var[var_0000]=[unescape];'A';"
        );

    SECTION("array pattern - let")
        test_normalization(
            "let [a] = [unescape]; a('%41');",
            "let[var_0000]=[unescape];'A';"
        );

    SECTION("array pattern - const")
        test_normalization(
            "const [a] = [unescape]; a('%41');",
            "const[var_0000]=[unescape];'A';"
        );

    SECTION("array pattern - char code")
        test_normalization(
            "var [a] = [String.fromCharCode]; a(65);",
            "var[var_0000]=[String.fromCharCode];'A';"
        );

    SECTION("object pattern - shorthand")
        test_normalization(
            "var {a} = {a:unescape}; a('%41');",
            "var{var_0000}={var_0000:unescape};'A';"
        );

    SECTION("object pattern - renamed")
        test_normalization(
            "var {x:a} = {x:unescape}; a('%41');",
            "var{var_0000:var_0001}={var_0000:unescape};'A';"
        );

    SECTION("array pattern - default value")
        test_normalization(
            "var [a = unescape] = []; a('%41');",
            "var[var_0000=unescape]=[];'A';"
        );

    SECTION("object pattern - default value")
        test_normalization(
            "var {a = unescape} = {}; a('%41');",
            "var{var_0000=unescape}={};'A';"
        );

    SECTION("default function parameter")
        test_normalization(
            "function f(a = unescape) { a('%41'); }",
            "function var_0000(var_0001=unescape){'A';}"
        );

    SECTION("parenthesized assignment")
        test_normalization(
            "(a = unescape); a('%41');",
            "(var_0000=unescape);'A';"
        );

    SECTION("re-assignment drops the alias")
        test_normalization(
            "var [a] = [unescape]; a = 1; a('%41');",
            "var[var_0000]=[unescape];unescape=1;var_0000('%41');"
        );

    SECTION("re-assignment drops the alias - simple declaration")
        test_normalization(
            "var a = unescape; a = 1; a('%41');",
            "var var_0000=unescape;unescape=1;var_0000('%41');"
        );

    SECTION("function call initializer is not an alias")
        test_normalization(
            "var a = f(1); a;",
            "var var_0000=var_0001(1);var_0000;"
        );

    SECTION("bracket accessor initializer is an alias")
        test_normalization(
            "var a = console['log']; a;",
            "var var_0000=console['log'];console['log'];"
        );

    SECTION("computed member initializer is not an alias")
        test_normalization(
            "var a = o[i]; a;",
            "var var_0000=var_0001[var_0002];var_0000;"
        );

    SECTION("object literal initializer is not an alias")
        test_normalization(
            "obj = {k:unescape}; obj('%41');",
            "var_0000={var_0001:unescape};var_0000('%41');"
        );
}

TEST_CASE("De-aliasing - binding patterns, unsupported forms", "[JSNormalizer]")
{
    SECTION("array pattern - more than one name")
        test_normalization(
            "var [a,b] = [console.log,unescape]; b('%41');",
            "var[var_0000,var_0001]=[console.log,unescape];var_0001('%41');"
        );

    SECTION("object pattern - more than one name")
        test_normalization(
            "var {a,b} = {a:console.log,b:unescape}; b('%41');",
            "var{var_0000,var_0001}={var_0000:console.log,var_0001:unescape};var_0001('%41');"
        );

    SECTION("more than one name - simple declaration")
        test_normalization(
            "var a = console.log, b = unescape; b('%41');",
            "var var_0000=console.log,var_0001=unescape;'A';"
        );

    SECTION("object pattern - untracked value")
        test_normalization(
            "var {a} = {a:o['log']}; a;",
            "var{var_0000}={var_0000:var_0001['log']};var_0000;"
        );

    SECTION("object pattern - untracked value in a longer path")
        test_normalization(
            "var {a} = {a:o.log}; a;",
            "var{var_0000}={var_0000:var_0001.var_0002};var_0000;"
        );

    SECTION("untracked value - simple declaration")
        test_normalization(
            "var a = o['log']; a;",
            "var var_0000=var_0001['log'];var_0000;"
        );
}

TEST_CASE("De-aliasing - binding patterns, scope", "[JSNormalizer]")
{
    SECTION("object pattern - trailing comma")
        test_normalization(
            "var {a} = {a:unescape,}; a('%41');",
            "var{var_0000}={var_0000:unescape,};'A';"
        );

    SECTION("object pattern - another property follows")
        test_normalization(
            "var {a} = {a:unescape,other:0}; a('%41');",
            "var{var_0000}={var_0000:unescape,var_0001:0};'A';"
        );

    SECTION("object pattern - two properties follow")
        test_normalization(
            "var {a} = {a:unescape,x:0,y:1}; a('%41');",
            "var{var_0000}={var_0000:unescape,var_0001:0,var_0002:1};'A';"
        );

    SECTION("array pattern - another element follows")
        test_normalization(
            "var [a] = [unescape,0]; a('%41');",
            "var[var_0000]=[unescape,0];'A';"
        );

    SECTION("function scope - binding does not escape")
        test_normalization(
            "var a = unescape; function f(){var a = console.log} a('%41');",
            "var var_0000=unescape;function var_0001(){var unescape=console.log}'A';"
        );

    SECTION("block scope - binding does not escape")
        test_normalization(
            "var a = unescape; {var a = console.log} a('%41');",
            "var var_0000=unescape;{var unescape=console.log}'A';"
        );

    SECTION("function scope - binding does not escape - simple declaration")
        test_normalization(
            "var a = unescape; function f(){var a = console.log;} a('%41');",
            "var var_0000=unescape;function var_0001(){var unescape=console.log;}'A';"
        );
}

TEST_CASE("De-aliasing - binding patterns, value selection", "[JSNormalizer]")
{
    SECTION("object pattern - selected property is second")
        test_normalization(
            "var {a} = {b:console.log,a:unescape}; a('%41');",
            "var{var_0000}={var_0001:console.log,var_0000:unescape};'A';"
        );

    SECTION("object pattern - renamed, selected property is second")
        test_normalization(
            "var {x:a} = {b:console.log,x:unescape}; a('%41');",
            "var{var_0000:var_0001}={var_0002:console.log,var_0000:unescape};'A';"
        );

    SECTION("object pattern - no property matches the key")
        test_normalization(
            "var {a} = {b:unescape}; a('%41');",
            "var{var_0000}={var_0001:unescape};var_0000('%41');"
        );

    SECTION("array pattern - default overridden by the supplied value")
        test_normalization(
            "var [a = console.log] = [unescape]; a('%41');",
            "var[var_0000=console.log]=[unescape];'A';"
        );

    SECTION("object pattern - default overridden by the supplied value")
        test_normalization(
            "var {a = console.log} = {a:unescape}; a('%41');",
            "var{var_0000=console.log}={var_0000:unescape};'A';"
        );

    SECTION("object pattern - default kept when no property matches")
        test_normalization(
            "var {a = unescape} = {b:console.log}; a('%41');",
            "var{var_0000=unescape}={var_0001:console.log};'A';"
        );

    SECTION("object pattern supplied by an array")
        test_normalization(
            "var {a} = [unescape]; a('%41');",
            "var{var_0000}=[unescape];var_0000('%41');"
        );

    SECTION("array pattern supplied by an object")
        test_normalization(
            "var [a] = {a:unescape}; a('%41');",
            "var[var_0000]={var_0000:unescape};var_0000('%41');"
        );

    SECTION("empty pattern")
        test_normalization(
            "var {} = {a:unescape}; a('%41');",
            "var{}={var_0000:unescape};var_0000('%41');"
        );
}

TEST_CASE("De-aliasing - binding patterns, value lifetime", "[JSNormalizer]")
{
    SECTION("object pattern - nested function scope follows the selected value")
        test_normalization(
            "var {a} = {a:unescape,other:function(){0;}}; a('%41');",
            "var{var_0000}={var_0000:unescape,var_0001:function(){0;}};'A';"
        );

    SECTION("array pattern - nested function scope follows the selected value")
        test_normalization(
            "var [a] = [unescape,function(){;}]; a('%41');",
            "var[var_0000]=[unescape,function(){;}];'A';"
        );

    SECTION("array pattern - bracket accessor call initializer")
        test_normalization(
            "var [a] = String['fromCharCode'](65); a;",
            "var[var_0000]=String['fromCharCode'](65);var_0000;"
        );

    SECTION("array pattern - bracket accessor call on an untracked object")
        test_normalization(
            "var [a] = o['log'](1); a;",
            "var[var_0000]=var_0001['log'](1);var_0000;"
        );

    SECTION("array pattern - more than one name, default on the first")
        test_normalization(
            "var [a = console.log,b] = [unescape,0]; a('%41');",
            "var[var_0000=console.log,var_0001]=[unescape,0];var_0000('%41');"
        );

    SECTION("object pattern - more than one name, default on the first")
        test_normalization(
            "var {a = console.log,b} = {a:unescape,b:0}; a('%41');",
            "var{var_0000=console.log,var_0001}={var_0000:unescape,var_0001:0};var_0000('%41');"
        );
}

TEST_CASE("De-aliasing - binding patterns, split identifier", "[JSNormalizer]")
{
    SECTION("renamed object pattern")
        test_normalization({
            {"var {x:ali", "var{var_0000:var_0001"},
            {"as} = {x:unescape}; alias('%41');",
                "var{var_0000:var_0002}={var_0000:unescape};'A';"}
        });

    SECTION("object pattern - shorthand")
        test_normalization({
            {"var {ali", "var{var_0000"},
            {"as} = {alias:unescape}; alias('%41');",
                "var{var_0001}={var_0001:unescape};'A';"}
        });

    SECTION("array pattern")
        test_normalization({
            {"var [ali", "var[var_0000"},
            {"as] = [unescape]; alias('%41');", "var[var_0001]=[unescape];'A';"}
        });

    SECTION("simple declaration")
        test_normalization({
            {"var ali", "var var_0000"},
            {"as = unescape; alias('%41');", "var var_0001=unescape;'A';"}
        });

    SECTION("supplier key")
        test_normalization({
            {"var {alias} = {ali", "var{var_0000}={var_0001"},
            {"as:unescape}; alias('%41');", "var{var_0000}={var_0000:unescape};'A';"}
        });

    SECTION("supplier key - renamed pattern")
        test_normalization({
            {"var {x:a} = {", "var{var_0000:var_0001}={"},
            {"x:unescape}; a('%41');", "var{var_0000:var_0001}={var_0000:unescape};'A';"}
        });

    // a split inside the value identifier loses the binding, as it does for a
    // simple assignment; see "alias value" above
    SECTION("inside the selected value")
        test_normalization({
            {"var {a} = {a:unes", "var{var_0000}={var_0000:var_0001"},
            {"cape}; a('%41');", "var{var_0000}={var_0000:unescape};var_0000('%41');"}
        });

    SECTION("inside a default")
        test_normalization({
            {"var [a = unes", "var[var_0000=var_0001"},
            {"cape] = []; a('%41');", "var[var_0000=unescape]=[];var_0000('%41');"}
        });

    SECTION("at the supplier close")
        test_normalization({
            {"var [a] = [unescape", "var[var_0000]=[unescape"},
            {"]; a('%41');", "var[var_0000]=[unescape];'A';"}
        });

    SECTION("before a duplicate key")
        test_normalization({
            {"var {a} = {a:console.log,", "var{var_0000}={var_0000:console.log,"},
            {"a:unescape}; a('%41');",
                "var{var_0000}={var_0000:console.log,var_0000:unescape};'A';"}
        });

    SECTION("inside a rejected pattern")
        test_normalization({
            {"var [a,b = console.log", "var[var_0000,var_0001=console.log"},
            {"] = [0,unescape]; b('%41');",
                "var[var_0000,var_0001=console.log]=[0,unescape];var_0001('%41');"}
        });

    SECTION("at an array hole")
        test_normalization({
            {"var [a = unescape] = [", "var[var_0000=unescape]=["},
            {",]; a('%41');", "var[var_0000=unescape]=[,];'A';"}
        });

    SECTION("before a spread")
        test_normalization({
            {"var {a = console.log} = {", "var{var_0000=console.log}={"},
            {"...o}; a('%41');", "var{var_0000=console.log}={...var_0001};var_0000('%41');"}
        });

    // the partial token is replayed, so the whole spread is recognized there
    SECTION("inside a spread")
        test_normalization({
            {"var {a = console.log} = {..", "var{var_0000=console.log}={.."},
            {".o}; a('%41');", "var{var_0000=console.log}={...var_0001};var_0000('%41');"}
        });

    SECTION("at a pattern default's '='")
        test_normalization({
            {"var {a =", "var{var_0000="},
            {" unescape} = {}; var {x:b} = {x:unescape}; b('%41');",
                "var{var_0000=unescape}={};var{var_0001:var_0002}={var_0001:unescape};'A';"}
        });

    SECTION("at a matching supplier colon")
        test_normalization({
            {"var {a = unescape} = {a:", "var{var_0000=unescape}={var_0000:"},
            {"0,a:undefined}; a('%41');",
                "var{var_0000=unescape}={var_0000:0,var_0000:undefined};'A';"}
        });

    SECTION("before an accessor on the supplying literal")
        test_normalization({
            {"var [a] = [unescape]", "var[var_0000]=[unescape]"},
            {".slice(0); a('%41');",
                "var[var_0000]=[unescape].var_0001(0);var_0000('%41');"}
        });

    SECTION("inside a shorthand supplier key")
        test_normalization({
            {"var {unescape:a} = {unesc", "var{unescape:var_0000}={var_0001"},
            {"ape}; a('%41');", "var{unescape:var_0000}={unescape};'A';"}
        });

    SECTION("at a shorthand supplier close")
        test_normalization({
            {"var {unescape:a} = {unescape", "var{unescape:var_0000}={unescape"},
            {"}; a('%41');", "var{unescape:var_0000}={unescape};'A';"}
        });

    SECTION("at a value nested in the supplier")
        test_normalization({
            {"var {a} = {b:{}", "var{var_0000}={var_0001:{}"},
            {",a:unescape}; a('%41');",
                "var{var_0000}={var_0001:{},var_0000:unescape};'A';"}
        });

    SECTION("at the '=' of a re-binding pattern")
        test_normalization({
            {"var a = unescape; var {x:a} =", "var var_0000=unescape;var{var_0001:unescape}="},
            {" {x:a}; a('%41');",
                "var var_0000=unescape;var{var_0001:unescape}={var_0001:unescape};'A';"}
        });

    SECTION("before an explicit undefined")
        test_normalization({
            {"var [a = unescape] = [", "var[var_0000=unescape]=["},
            {"undefined]; a('%41');", "var[var_0000=unescape]=[undefined];'A';"}
        });
}

TEST_CASE("De-aliasing - binding patterns, selection conformance", "[JSNormalizer]")
{
    // the value recorded is the one an ECMAScript engine binds
    SECTION("object pattern - unrelated property precedes the selected one")
        test_normalization(
            "var {a} = {b:0,a:unescape}; a('%41');",
            "var{var_0000}={var_0001:0,var_0000:unescape};'A';"
        );

    SECTION("object pattern - unrelated untracked value precedes the selected one")
        test_normalization(
            "var {a} = {b:o,a:unescape}; a('%41');",
            "var{var_0000}={var_0001:var_0002,var_0000:unescape};'A';"
        );

    SECTION("object pattern - default survives an unrelated property")
        test_normalization(
            "var {a = unescape} = {b:0}; a('%41');",
            "var{var_0000=unescape}={var_0001:0};'A';"
        );

    SECTION("object pattern - duplicate key binds the last definition")
        test_normalization(
            "var {a} = {a:console.log,a:unescape}; a('%41');",
            "var{var_0000}={var_0000:console.log,var_0000:unescape};'A';"
        );

    SECTION("object pattern - duplicate key, last definition is not a decoder")
        test_normalization(
            "var {a} = {a:unescape,a:console.log}; a('%41');",
            "var{var_0000}={var_0000:unescape,var_0000:console.log};console.log('%41');"
        );

    SECTION("array pattern - only the first element is selected")
        test_normalization(
            "var [a] = [console.log,unescape]; a('%41');",
            "var[var_0000]=[console.log,unescape];console.log('%41');"
        );

    SECTION("array pattern - default is not aliasable")
        test_normalization(
            "var [a = 0] = [unescape]; a('%41');",
            "var[var_0000=0]=[unescape];'A';"
        );

    SECTION("object pattern - default is not aliasable")
        test_normalization(
            "var {a = 0} = {a:unescape}; a('%41');",
            "var{var_0000=0}={var_0000:unescape};'A';"
        );

    SECTION("array pattern - hole selects the default")
        test_normalization(
            "var [a = unescape] = [,]; a('%41');",
            "var[var_0000=unescape]=[,];'A';"
        );

    SECTION("array pattern - supplied value overrides the default")
        test_normalization(
            "var [a = unescape] = [0]; a('%41');",
            "var[var_0000=unescape]=[0];var_0000('%41');"
        );

    SECTION("object pattern - supplied value overrides the default")
        test_normalization(
            "var {a = unescape} = {a:0}; a('%41');",
            "var{var_0000=unescape}={var_0000:0};var_0000('%41');"
        );

    SECTION("array pattern - default expression in a group")
        test_normalization(
            "var [a = f()] = [unescape]; a('%41');",
            "var[var_0000=var_0001()]=[unescape];'A';"
        );
}

TEST_CASE("De-aliasing - binding patterns, declined initializers", "[JSNormalizer]")
{
    // a pattern selects out of the literal on the other side of '=' only
    SECTION("array pattern - nested array value")
        test_normalization(
            "var [a] = [[unescape]]; a;",
            "var[var_0000]=[[unescape]];var_0000;"
        );

    SECTION("object pattern - nested object value")
        test_normalization(
            "var {a} = {a:{b:unescape}}; a('%41');",
            "var{var_0000}={var_0000:{var_0001:unescape}};var_0000('%41');"
        );

    SECTION("array pattern - accessor on the supplying literal")
        test_normalization(
            "var [a] = [console.log,unescape].slice(1); a('%41');",
            "var[var_0000]=[console.log,unescape].var_0001(1);var_0000('%41');"
        );

    SECTION("object pattern - supplier is not a literal")
        test_normalization(
            "var {fromCharCode:a} = String; a(65);",
            "var{var_0000:var_0001}=String;var_0001(65);"
        );

    SECTION("array pattern - more than one name, default on the last")
        test_normalization(
            "var [a,b = console.log] = [0,unescape]; b('%41');",
            "var[var_0000,var_0001=console.log]=[0,unescape];var_0001('%41');"
        );

    SECTION("nested array pattern")
        test_normalization(
            "var [[a]] = [[unescape]]; a('%41');",
            "var[[var_0000]]=[[unescape]];var_0000('%41');"
        );

    SECTION("nested object pattern")
        test_normalization(
            "var {a:{b}} = {a:{b:unescape}}; b('%41');",
            "var{var_0000:{var_0001}}={var_0000:{var_0001:unescape}};var_0001('%41');"
        );

    // only a group and a literal are skipped as supplied values; a parenthesised
    // value and a template substitution are not, so the binding declines there
    SECTION("parenthesised value before the selected property")
        test_normalization(
            "var {a} = {b:(0),a:unescape}; a('%41');",
            "var{var_0000}={var_0001:(0),var_0000:unescape};var_0000('%41');"
        );

    SECTION("template substitution before the selected property")
        test_normalization(
            "var {a} = {b:`${0}`,a:unescape}; a('%41');",
            "var{var_0000}={var_0001:`${0}`,var_0000:unescape};var_0000('%41');"
        );
}

TEST_CASE("De-aliasing - binding patterns, re-binding an aliased name", "[JSNormalizer]")
{
    // re-binding stops the old alias substituting, whatever the pattern records
    SECTION("renamed pattern")
        test_normalization(
            "var a = unescape; var {b:a} = c; a('%41');",
            "var var_0000=unescape;var{var_0001:unescape}=var_0002;var_0000('%41');"
        );

    SECTION("shorthand pattern")
        test_normalization(
            "var a = unescape; var {a} = b; a('%41');",
            "var var_0000=unescape;var{unescape}=var_0001;var_0000('%41');"
        );

    SECTION("array pattern")
        test_normalization(
            "var a = unescape; var [a] = [0]; a('%41');",
            "var var_0000=unescape;var[unescape]=[0];var_0000('%41');"
        );

    SECTION("defeated default")
        test_normalization(
            "var a = unescape; var [a = 0] = []; a('%41');",
            "var var_0000=unescape;var[unescape=0]=[];var_0000('%41');"
        );

    SECTION("declined supplier")
        test_normalization(
            "var a = unescape; var {x:a} = String; a('%41');",
            "var var_0000=unescape;var{var_0001:unescape}=String;var_0000('%41');"
        );

    SECTION("a successful re-bind records the new value")
        test_normalization(
            "var a = console.log; var {a} = {a:unescape}; a('%41');",
            "var var_0000=console.log;var{console.log}={console.log:unescape};'A';"
        );

    SECTION("simple assignment")
        test_normalization(
            "var a = unescape; a = 0; a('%41');",
            "var var_0000=unescape;unescape=0;var_0000('%41');"
        );
}

TEST_CASE("De-aliasing - binding patterns, tracking survives a declaration", "[JSNormalizer]")
{
    // an ordinary pattern declaration must not leave tracking disabled
    SECTION("later simple alias")
        test_normalization(
            "var {b} = d; var e = unescape; e('%41');",
            "var{var_0000}=var_0001;var var_0002=unescape;'A';"
        );

    SECTION("later pattern alias")
        test_normalization(
            "var {b} = d; var {e} = {e:unescape}; e('%41');",
            "var{var_0000}=var_0001;var{var_0002}={var_0002:unescape};'A';"
        );

    SECTION("two declarations then an alias")
        test_normalization(
            "var {b} = d; var {f} = g; var h = unescape; h('%41');",
            "var{var_0000}=var_0001;var{var_0002}=var_0003;var var_0004=unescape;'A';"
        );
}

TEST_CASE("De-aliasing - binding patterns, alias entry cap", "[JSNormalizer]")
{
    // one binding spends one entry, whatever the pattern read to find it
    SECTION("a pattern binding spends one entry")
        default_config.test_normalization(
            "var {a} = {a:unescape}; a('%41');",
            "var{var_0000}={var_0000:unescape};'A';",
            {identifier_depth(1), check_alias_limit_reached(false)}
        );

    SECTION("a duplicate key still spends one entry")
        default_config.test_normalization(
            "var {a} = {a:console.log,a:unescape}; a('%41');",
            "var{var_0000}={var_0000:console.log,var_0000:unescape};'A';",
            {identifier_depth(2), check_alias_limit_reached(false)}
        );

    SECTION("two pattern bindings spend two entries")
        default_config.test_normalization(
            "var {a} = {a:unescape}; var {b} = {b:unescape}; a('%41'); b('%42');",
            "var{var_0000}={var_0000:unescape};var{var_0001}={var_0001:unescape};'A';'B';",
            {identifier_depth(2), check_alias_limit_reached(false)}
        );

    SECTION("re-assigning a pattern-bound name exhausts the cap")
        default_config.test_normalization(
            "var {a} = {a:unescape}; a = console;",
            "var{var_0000}={var_0000:unescape};unescape=console;",
            {identifier_depth(1), check_alias_limit_reached(true)}
        );
}

TEST_CASE("De-aliasing - binding patterns, state does not outlive the pattern",
    "[JSNormalizer]")
{
    // a pattern that bound nothing leaves the next binding free to be tracked
    SECTION("assignment after a defeated object default")
        test_normalization(
            "var {a = unescape} = {a:0}; b = unescape; b('%41');",
            "var{var_0000=unescape}={var_0000:0};var_0001=unescape;'A';"
        );

    SECTION("declarator after a defeated object default")
        test_normalization(
            "var {a = unescape} = {a:0}, b = unescape; b('%41');",
            "var{var_0000=unescape}={var_0000:0},var_0001=unescape;'A';"
        );

    SECTION("assignment after a declined supplier")
        test_normalization(
            "var {fromCharCode:a} = String; b = unescape; b('%41');",
            "var{var_0000:var_0001}=String;var_0002=unescape;'A';"
        );

    SECTION("pattern after a defeated object default")
        test_normalization(
            "var {a = unescape} = {a:0}; var [b] = [unescape]; b('%41');",
            "var{var_0000=unescape}={var_0000:0};var[var_0001]=[unescape];'A';"
        );
}

TEST_CASE("De-aliasing - binding patterns, state does not cross a script end",
    "[JSNormalizer]")
{
    // the next script is a fresh program, so a pattern left open by the one
    // before it settles nothing about the names the next one binds
    SECTION("a script ending inside a spread operand")
        test_normalization(
            "var {a}={...o</script>",
            "var{var_0000}={...var_0001",
            {return_code(JSTokenizer::ENDED_IN_INNER_SCOPE)}
        );

    SECTION("the next script still binds")
        test_normalization({
            {"var {a}={...o</script>", "var{var_0000}={...var_0001"},
            {"var b=unescape; b('%41');",
                "var{var_0000}={...var_0001var var_0002=unescape;'A';"}
        });

    SECTION("the next script still binds after a complete script")
        test_normalization({
            {"var x=0;</script>", "var var_0000=0;"},
            {"var b=unescape; b('%41');", "var var_0000=0;var var_0001=unescape;'A';"}
        });
}

TEST_CASE("De-aliasing - binding patterns, nested declaration", "[JSNormalizer]")
{
    // a declaration inside the supplier does not own the pending binding
    SECTION("object supplier holds a declaration")
        test_normalization(
            "var {a} = {a:unescape,other:function(){var b=0;}}; a('%41');",
            "var{var_0000}={var_0000:unescape,var_0001:function(){var var_0002=0;}};'A';"
        );

    SECTION("array supplier holds a declaration")
        test_normalization(
            "var [a] = [unescape,function(){var b=0;}]; a('%41');",
            "var[var_0000]=[unescape,function(){var var_0001=0;}];'A';"
        );

    // a declaration in a spread operand owns no position of the literal, but it
    // is still a binding of its own
    SECTION("spread operand holds a declaration")
        test_normalization(
            "var {a} = {...o(function(){var b=unescape; b('%41');})}; a('%41');",
            "var{var_0000}={...var_0001(function(){var var_0002=unescape;'A';})};"
                "var_0000('%41');"
        );

    SECTION("spread operand holds a declaration, value already selected")
        test_normalization(
            "var [a] = [unescape,...o(function(){var b=0;})]; a('%41');",
            "var[var_0000]=[unescape,...var_0001(function(){var var_0002=0;})];'A';"
        );
}

TEST_CASE("De-aliasing - binding patterns, supplier property boundaries", "[JSNormalizer]")
{
    // a key belongs to the property it opens, and a key that cannot be read
    // leaves that position unresolved rather than empty
    SECTION("quoted supplier key")
        test_normalization(
            "var {a = console.log} = {'a':unescape}; a('%41');",
            "var{var_0000=console.log}={'a':unescape};var_0000('%41');"
        );

    SECTION("quoted supplier key under a renamed pattern")
        test_normalization(
            "var {x:a = console.log} = {'x':unescape}; a('%41');",
            "var{var_0000:var_0001=console.log}={'x':unescape};var_0001('%41');"
        );

    SECTION("computed supplier key")
        test_normalization(
            "var {a = console.log} = {['a']:unescape}; a('%41');",
            "var{var_0000=console.log}={['a']:unescape};var_0000('%41');"
        );

    SECTION("conditional value matches no key")
        test_normalization(
            "var {a} = {a:1?unescape:console.log}; a('%41');",
            "var{var_0000}={var_0000:1?unescape:console.log};var_0000('%41');"
        );

    SECTION("shorthand supplier property")
        test_normalization(
            "var {unescape:a = console.log} = {unescape}; a('%41');",
            "var{unescape:var_0000=console.log}={unescape};'A';"
        );

    SECTION("shorthand supplier property of an aliased name")
        test_normalization(
            "var b = unescape; var {b:a = console.log} = {b}; a('%41');",
            "var var_0000=unescape;var{unescape:var_0001=console.log}={unescape};'A';"
        );

    SECTION("shorthand supplier property under another key")
        test_normalization(
            "var b = 0; var {a = unescape} = {b}; a('%41');",
            "var var_0000=0;var{var_0001=unescape}={var_0000};'A';"
        );
}

TEST_CASE("De-aliasing - binding patterns, duplicate supplier keys", "[JSNormalizer]")
{
    // the last definition under the pattern's key is the one that is bound
    SECTION("numeric replacement")
        test_normalization(
            "var {a} = {a:unescape,a:0}; a('%41');",
            "var{var_0000}={var_0000:unescape,var_0000:0};var_0000('%41');"
        );

    SECTION("grouped replacement")
        test_normalization(
            "var {a} = {a:console.log,a:(unescape)}; a('%41');",
            "var{var_0000}={var_0000:console.log,var_0000:(unescape)};var_0000('%41');"
        );

    SECTION("operator-valued replacement")
        test_normalization(
            "var {a} = {a:console.log,a:unescape||console.log}; a('%41');",
            "var{var_0000}={var_0000:console.log,var_0000:unescape||console.log};var_0000('%41');"
        );
}

TEST_CASE("De-aliasing - binding patterns, value nested in the supplier", "[JSNormalizer]")
{
    // a value nested in the supplying literal is skipped, and the pending
    // binding belongs to that literal, not to the scope the value closes in
    SECTION("empty object before the selected property")
        test_normalization(
            "var {a} = {b:{},a:unescape}; a('%41');",
            "var{var_0000}={var_0001:{},var_0000:unescape};'A';"
        );

    SECTION("nonempty object before the selected property")
        test_normalization(
            "var {a} = {b:{x:0},a:unescape}; a('%41');",
            "var{var_0000}={var_0001:{var_0002:0},var_0000:unescape};'A';"
        );

    SECTION("nested array before the selected property")
        test_normalization(
            "var {a} = {b:[0,1],a:unescape}; a('%41');",
            "var{var_0000}={var_0001:[0,1],var_0000:unescape};'A';"
        );

    // a function body is not a value the pattern selects through, so a
    // declaration in one is left exactly as it is without a pattern present:
    // untracked, because identifier normalization is off in an object-literal
    // function value for reasons older than binding patterns
    SECTION("a declaration in an object-literal function value is untracked")
        test_normalization(
            "var o = {f:function(){var u = unescape; u('%41');}};",
            "var var_0000={var_0001:function(){var u=unescape;u('%41');}};"
        );

    SECTION("the supplier does not change that")
        test_normalization(
            "var {a} = {a:0,f:function(){var u = unescape; u('%41');}}; a('%41');",
            "var{var_0000}={var_0000:0,var_0001:function(){var u=unescape;u('%41');}};"
                "var_0000('%41');"
        );
}

TEST_CASE("De-aliasing - binding patterns, explicit undefined", "[JSNormalizer]")
{
    // undefined is the one supplied value a destructuring default replaces
    SECTION("array pattern")
        test_normalization(
            "var [a = unescape] = [undefined]; a('%41');",
            "var[var_0000=unescape]=[undefined];'A';"
        );

    SECTION("object pattern")
        test_normalization(
            "var {a = unescape} = {a:undefined}; a('%41');",
            "var{var_0000=unescape}={var_0000:undefined};'A';"
        );

    SECTION("null does not replace the default")
        test_normalization(
            "var [a = unescape] = [null]; a('%41');",
            "var[var_0000=unescape]=[null];var_0000('%41');"
        );
}

TEST_CASE("De-aliasing - binding patterns, the initializer sees the old alias",
    "[JSNormalizer]")
{
    // the name is re-bound where the initializer ends, so the initializer still
    // reads the value that name carried going in
    SECTION("renamed pattern reads the name it binds")
        test_normalization(
            "var a = unescape; var {x:a} = {b:0,x:a}; a('%41');",
            "var var_0000=unescape;var{var_0001:unescape}={var_0002:0,var_0001:unescape};'A';"
        );

    SECTION("default-bearing pattern reads the name it binds")
        test_normalization(
            "var a = unescape; var [a = 0] = [a]; a('%41');",
            "var var_0000=unescape;var[unescape=0]=[unescape];'A';"
        );

    SECTION("a pattern that binds nothing still stops the old alias")
        test_normalization(
            "var a = unescape; var {x:a} = {b:0}; a('%41');",
            "var var_0000=unescape;var{var_0001:unescape}={var_0002:0};var_0000('%41');"
        );
}

TEST_CASE("De-aliasing - binding patterns, unselected element with a constructor",
    "[JSNormalizer]")
{
    // an element the pattern does not select registers nothing, so the one it
    // does select is the only alias entry the statement spends
    SECTION("one entry is enough for the selected element")
        default_config.test_normalization(
            "var [a] = [unescape,new String()]; a('%41');",
            "var[var_0000]=[unescape,new String()];'A';",
            {identifier_depth(1), check_alias_limit_reached(false)}
        );

    SECTION("the selected element is bound with no cap in the way")
        test_normalization(
            "var [a] = [unescape,new String()]; a('%41');",
            "var[var_0000]=[unescape,new String()];'A';"
        );
}

TEST_CASE("De-aliasing - binding patterns, object spread in the supplier", "[JSNormalizer]")
{
    // a spread may carry the key the pattern selects, so it is not evidence the
    // position is empty: the default declines unless a later property settles it
    SECTION("spread of a name")
        test_normalization(
            "var o = {a:unescape}; var {a = console.log} = {...o}; a('%41');",
            "var var_0000={var_0001:unescape};var{var_0001=console.log}={...var_0000};"
                "var_0001('%41');"
        );

    SECTION("spread of an inline literal")
        test_normalization(
            "var {a = console.log} = {...{a:unescape}}; a('%41');",
            "var{var_0000=console.log}={...{var_0000:unescape}};var_0000('%41');"
        );

    SECTION("spread after the selected property")
        test_normalization(
            "var {a} = {a:unescape,...o}; a('%41');",
            "var{var_0000}={var_0000:unescape,...var_0001};var_0000('%41');"
        );

    SECTION("an explicit property after a spread still settles the value")
        test_normalization(
            "var {a} = {...o,a:unescape}; a('%41');",
            "var{var_0000}={...var_0001,var_0000:unescape};'A';"
        );

    // an array supplies by position, so its first element is already selected
    SECTION("array spread")
        test_normalization(
            "var [a = console.log] = [...arr]; a('%41');",
            "var[var_0000=console.log]=[...var_0001];var_0000('%41');"
        );

    // a rest element binds a fresh object, not the property it collected
    SECTION("rest element in the pattern")
        test_normalization(
            "var {...r} = {r:unescape}; r('%41');",
            "var{...var_0000}={var_0000:unescape};var_0000('%41');"
        );

    SECTION("spread outside a pattern")
        test_normalization(
            "var a = [...b]; a('%41');",
            "var var_0000=[...var_0001];var_0000('%41');"
        );

    // a spread in a value nested in the supplier reaches none of the supplier's
    // own keys, so it leaves the selected property standing
    SECTION("a spread in a value nested in the supplier")
        test_normalization(
            "var {a} = {a:unescape,b:{...o}}; a('%41');",
            "var{var_0000}={var_0000:unescape,var_0001:{...var_0002}};'A';"
        );

    // the operand is the object being spread, not a property of the literal it
    // is spread into, so it keys no position and supplies no value
    SECTION("the operand names the key the pattern selects")
        test_normalization(
            "var {unescape:a = console.log} = {...unescape}; a('%41');",
            "var{unescape:var_0000=console.log}={...unescape};var_0000('%41');"
        );

    SECTION("the operand names the key and carries a tracked value")
        test_normalization(
            "var o = console.log; var {o:a = unescape} = {...o}; a('%41');",
            "var var_0000=console.log;var{console.log:var_0001=unescape}="
                "{...console.log};var_0001('%41');"
        );

    SECTION("the operand split across PDUs")
        test_normalization({
            {"var {unescape:a = console.log} = {...unes",
                "var{unescape:var_0000=console.log}={...var_0001"},
            {"cape}; a('%41');",
                "var{unescape:var_0000=console.log}={...unescape};var_0000('%41');"}
        });
}

TEST_CASE("De-aliasing - binding patterns, array spread in the supplier", "[JSNormalizer]")
{
    // an array supplies by position and a spread only appends, so one past the
    // selected position leaves what that position already holds
    SECTION("spread after the selected element")
        test_normalization(
            "var [a] = [unescape,...[]]; a('%41');",
            "var[var_0000]=[unescape,...[]];'A';"
        );

    SECTION("spread of a name after the selected element")
        test_normalization(
            "var [a] = [unescape,...o]; a('%41');",
            "var[var_0000]=[unescape,...var_0001];'A';"
        );

    SECTION("a first-position hole still takes the default")
        test_normalization(
            "var [a = unescape] = [,...o]; a('%41');",
            "var[var_0000=unescape]=[,...var_0001];'A';"
        );

    // a spread in the selected position can supply anything
    SECTION("spread in the selected element")
        test_normalization(
            "var [a] = [...[unescape]]; a('%41');",
            "var[var_0000]=[...[unescape]];var_0000('%41');"
        );

    // the operand is the array being spread, so it keys no position of this one
    SECTION("the operand carries a tracked value")
        test_normalization(
            "var [a = console.log] = [0,...unescape]; a('%41');",
            "var[var_0000=console.log]=[0,...unescape];var_0000('%41');"
        );
}

TEST_CASE("De-aliasing - binding patterns, default stays provisional", "[JSNormalizer]")
{
    // the supplier closing is not the end of the initializer, so a postfix on it
    // can still take the value away from the default
    SECTION("accessor and call on an empty array supplier")
        test_normalization(
            "var [a = console.log] = [].concat([unescape]); a('%41');",
            "var[var_0000=console.log]=[].var_0001([unescape]);var_0000('%41');"
        );

    // declining here is a miss rather than a mis-binding: the engine does read
    // undefined off this accessor, but nothing proves that to the tracker
    SECTION("accessor on an empty object supplier")
        test_normalization(
            "var {a = console.log} = {}.x; a('%41');",
            "var{var_0000=console.log}={}.var_0001;var_0000('%41');"
        );

    SECTION("empty array supplier still takes the default")
        test_normalization(
            "var [a = unescape] = []; a('%41');",
            "var[var_0000=unescape]=[];'A';"
        );

    SECTION("empty object supplier still takes the default")
        test_normalization(
            "var {a = unescape} = {}; a('%41');",
            "var{var_0000=unescape}={};'A';"
        );
}

TEST_CASE("De-aliasing - binding patterns, replacement under a matching key",
    "[JSNormalizer]")
{
    // a matching position replaces what an earlier one supplied even when its own
    // value cannot be carried, and restores the default it is eligible for
    SECTION("shorthand replaces a tracked value")
        test_normalization(
            "var a = 0; var {a:b} = {a:unescape,a}; b('%41');",
            "var var_0000=0;var{var_0000:var_0001}={var_0000:unescape,var_0000};"
                "var_0001('%41');"
        );

    SECTION("a shorthand under another key replaces nothing")
        test_normalization(
            "var {a} = {a:unescape,b}; a('%41');",
            "var{var_0000}={var_0000:unescape,var_0001};'A';"
        );

    SECTION("an unreadable key may be the replacement")
        test_normalization(
            "var {a} = {a:console.log,'a':unescape}; a('%41');",
            "var{var_0000}={var_0000:console.log,'a':unescape};var_0000('%41');"
        );

    SECTION("a computed key may be the replacement")
        test_normalization(
            "var {a} = {a:console.log,['a']:unescape}; a('%41');",
            "var{var_0000}={var_0000:console.log,['a']:unescape};var_0000('%41');"
        );

    // a colon inside a value is not a key, so it settles nothing either way
    SECTION("a conditional in an unrelated value keeps the selection")
        test_normalization(
            "var {a} = {a:unescape,b:1?x:y}; a('%41');",
            "var{var_0000}={var_0000:unescape,var_0001:1?var_0002:var_0003};'A';"
        );

    SECTION("a conditional of literals keeps the selection")
        test_normalization(
            "var {a} = {a:unescape,b:1?0:2}; a('%41');",
            "var{var_0000}={var_0000:unescape,var_0001:1?0:2};'A';"
        );

    SECTION("a replacement restores default eligibility")
        test_normalization(
            "var {a = unescape} = {a:0,a:undefined}; a('%41');",
            "var{var_0000=unescape}={var_0000:0,var_0000:undefined};'A';"
        );

    SECTION("a replacement can also defeat the default")
        test_normalization(
            "var {a = unescape} = {a:undefined,a:0}; a('%41');",
            "var{var_0000=unescape}={var_0000:undefined,var_0000:0};var_0000('%41');"
        );
}

TEST_CASE("De-aliasing - binding patterns, absent selected array position",
    "[JSNormalizer]")
{
    // the selected position decides the default on its own; a later element does
    // not supply it
    SECTION("hole before a value")
        test_normalization(
            "var [a = unescape] = [,0]; a('%41');",
            "var[var_0000=unescape]=[,0];'A';"
        );

    SECTION("value in the selected position")
        test_normalization(
            "var [a = unescape] = [0,1]; a('%41');",
            "var[var_0000=unescape]=[0,1];var_0000('%41');"
        );

    SECTION("hole before the decoder keeps the default")
        test_normalization(
            "var [a = console.log] = [,unescape]; a('%41');",
            "var[var_0000=console.log]=[,unescape];console.log('%41');"
        );
}

TEST_CASE("De-aliasing - binding patterns, inherited key declines the default",
    "[JSNormalizer]")
{
    // no own property does not mean undefined when the key names one the
    // prototype chain carries, so the default does not stand there
    SECTION("renamed pattern on a prototype key")
        test_normalization(
            "var {toString:a = unescape} = {}; a('%41');",
            "var{var_0000:var_0001=unescape}={};var_0001('%41');"
        );

    SECTION("shorthand pattern on a prototype key")
        test_normalization(
            "var {valueOf = unescape} = {}; valueOf('%41');",
            "var{var_0000=unescape}={};var_0000('%41');"
        );

    SECTION("an own property shadows the prototype")
        test_normalization(
            "var {toString:a} = {toString:unescape}; a('%41');",
            "var{var_0000:var_0001}={var_0000:unescape};'A';"
        );

    // an own property under a prototype key is still the absence the default
    // stands in for, and the prototype no longer reaches the name
    SECTION("an own undefined property still takes the default")
        test_normalization(
            "var {toString:a = unescape} = {toString:undefined}; a('%41');",
            "var{var_0000:var_0001=unescape}={var_0000:undefined};'A';"
        );

    SECTION("an ordinary key still takes the default")
        test_normalization(
            "var {a = unescape} = {}; a('%41');",
            "var{var_0000=unescape}={};'A';"
        );
}

TEST_CASE("De-aliasing - binding patterns, accessor property in the supplier",
    "[JSNormalizer]")
{
    // an accessor defines the property through code, so a matching one supplies
    // nothing this tracker can read and leaves no earlier selection standing
    SECTION("a getter replaces a tracked value")
        test_normalization(
            "var {a} = {a:unescape,get a(){return console.log;}}; a('%41');",
            "var{var_0000}={var_0000:unescape,var_0001 var_0000(){"
                "return console.log;}};var_0000('%41');"
        );

    SECTION("a getter replaces an untracked value")
        test_normalization(
            "var {a} = {a:console.log,get a(){return unescape;}}; a('%41');",
            "var{var_0000}={var_0000:console.log,var_0001 var_0000(){"
                "return unescape;}};var_0000('%41');"
        );

    SECTION("a getter under another key keeps the selection")
        test_normalization(
            "var {a} = {a:unescape,get b(){return console.log;}}; a('%41');",
            "var{var_0000}={var_0000:unescape,var_0001 var_0002(){"
                "return console.log;}};'A';"
        );
}

TEST_CASE("De-aliasing - binding patterns, method key the tracker cannot read",
    "[JSNormalizer]")
{
    // a method whose key this tracker has not read may be defining the key the
    // pattern selects, so no earlier selection is left standing
    SECTION("quoted method key")
        test_normalization(
            "var {a} = {a:unescape,'a'(){}}; a('%41');",
            "var{var_0000}={var_0000:unescape,'a'(){}};var_0000('%41');"
        );

    SECTION("computed method key")
        test_normalization(
            "var {a} = {a:unescape,['a'](){}}; a('%41');",
            "var{var_0000}={var_0000:unescape,['a'](){}};var_0000('%41');"
        );

    SECTION("quoted accessor key")
        test_normalization(
            "var {a} = {a:unescape,get 'a'(){return console.log;}}; a('%41');",
            "var{var_0000}={var_0000:unescape,var_0001 'a'(){"
                "return console.log;}};var_0000('%41');"
        );

    // a key the tracker did read settles the position on its own merits
    SECTION("method key naming the selected key")
        test_normalization(
            "var {a} = {a:unescape,a(){}}; a('%41');",
            "var{var_0000}={var_0000:unescape,var_0000(){}};var_0000('%41');"
        );

    SECTION("method key naming another key")
        test_normalization(
            "var {a} = {a:unescape,b(){}}; a('%41');",
            "var{var_0000}={var_0000:unescape,var_0001(){}};'A';"
        );
}

TEST_CASE("De-aliasing - binding patterns, prototype set in the supplier",
    "[JSNormalizer]")
{
    // a literal that sets a prototype this tracker has not read leaves the keys
    // it has no own property for unresolved, so no default stands there
    SECTION("an unresolved prototype declines the default")
        test_normalization(
            "var {a = unescape} = {__proto__:{a:console.log}}; a('%41');",
            "var{var_0000=unescape}={var_0001:{var_0000:console.log}};"
                "var_0000('%41');"
        );

    SECTION("an own property settles it regardless")
        test_normalization(
            "var {a = unescape} = {__proto__:{a:console.log},a:unescape}; a('%41');",
            "var{var_0000=unescape}={var_0001:{var_0000:console.log},"
                "var_0000:unescape};'A';"
        );
}

TEST_CASE("De-aliasing - binding patterns, conditional in a pattern default",
    "[JSNormalizer]")
{
    // past the default's '=' a colon belongs to that default's value, so it
    // discards the default without renaming what the pattern binds
    SECTION("the supplier settles the value")
        test_normalization(
            "var {a = 0?x:y} = {a:unescape}; a('%41');",
            "var{var_0000=0?var_0001:var_0002}={var_0000:unescape};'A';"
        );

    SECTION("the rename colon still names the bound value")
        test_normalization(
            "var {x:a} = {x:unescape}; a('%41');",
            "var{var_0000:var_0001}={var_0000:unescape};'A';"
        );

    SECTION("a rename with a default still selects the supplied value")
        test_normalization(
            "var {x:a = console.log} = {x:unescape}; a('%41');",
            "var{var_0000:var_0001=console.log}={var_0000:unescape};'A';"
        );
}

TEST_CASE("De-aliasing - constructor alias accounting", "[JSNormalizer]")
{
    // registering a constructor alias is the re-binding, so nothing is left to
    // retire and the statement spends one entry
    SECTION("a simple constructor assignment spends one entry")
        default_config.test_normalization(
            "a = new String();",
            "var_0000=new String();",
            {identifier_depth(1), check_alias_limit_reached(false)}
        );

    SECTION("a later alias still fits the cap")
        default_config.test_normalization(
            "a = new String(); b = eval; b(\"2 + 2\");",
            "var_0000=new String();var_0001=eval;eval(\"2 + 2\");",
            {identifier_depth(2), check_alias_limit_reached(false)}
        );
}

TEST_CASE("De-aliasing - binding patterns, constructor value in the supplier",
    "[JSNormalizer]")
{
    // a constructor call yields an instance, which carries none of the statics
    // the tracked names are, so the supplier declines it
    SECTION("array supplier, no parentheses")
        test_normalization(
            "var [a] = [new String]; a.fromCharCode(65);",
            "var[var_0000]=[new String];var_0000.var_0001(65);"
        );

    // in an object literal 'new' reads as a property name, which is older than
    // binding patterns and declines the value for its own reason
    SECTION("object supplier, no parentheses")
        test_normalization(
            "var {a} = {a:new String}; a.fromCharCode(65);",
            "var{var_0000}={var_0000:var_0001 String};var_0000.var_0002(65);"
        );

    SECTION("a constructor in the selected element binds nothing")
        test_normalization(
            "var [a] = [new String,unescape]; a('%41');",
            "var[var_0000]=[new String,unescape];var_0000('%41');"
        );

    // a constructor the tracker cannot carry is a default like any other: the
    // supplied value stands in its place and the name stays bound
    SECTION("a constructor default yields to the supplied value")
        test_normalization(
            "var [a = new String()] = [unescape]; a('%41');",
            "var[var_0000=new String()]=[unescape];'A';"
        );
}

#endif // CATCH_TEST_BUILD

