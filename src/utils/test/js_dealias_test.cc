//--------------------------------------------------------------------------
// Copyright (C) 2021-2022 Cisco and/or its affiliates. All rights reserved.
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

#include "utils/test/js_test_utils.h"

using namespace snort;

// Unit tests

#ifdef CATCH_TEST_BUILD

TEST_CASE("De-aliasing - basic", "[JSNormalizer]")
{
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

#endif // CATCH_TEST_BUILD

