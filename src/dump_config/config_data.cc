//--------------------------------------------------------------------------
// Copyright (C) 2020-2024 Cisco and/or its affiliates. All rights reserved.
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
// config_data.cc author Serhii Vlasiuk <svlasiuk@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "config_data.h"

#include <cassert>

using namespace snort;

BaseConfigNode::BaseConfigNode(BaseConfigNode* p) :
    parent(p)
{}

void BaseConfigNode::add_child_node(BaseConfigNode* node)
{
    assert(node);
    children.push_back(node);
}

void BaseConfigNode::clear_nodes(BaseConfigNode* node)
{
    for ( auto& config_node : node->children )
        clear_nodes(config_node);

    delete node;
}

void BaseConfigNode::sort_nodes(BaseConfigNode* node)
{
    if ( !node->children.empty() )
    {
        node->children.sort([](const BaseConfigNode* l, const BaseConfigNode* r)
            { return l->get_name() < r->get_name(); });

        for ( auto& config_node : node->children )
            sort_nodes(config_node);
    }
}

TreeConfigNode::TreeConfigNode(BaseConfigNode* parent_node,
    const std::string& node_name, const Parameter::Type node_type) :
        BaseConfigNode(parent_node), name(node_name), type(node_type)
{}

BaseConfigNode* TreeConfigNode::get_node(const std::string& name)
{
    auto it = std::find_if(children.cbegin(), children.cend(),
        [name](BaseConfigNode* node){ return node->get_name() == name; });
    return it != children.cend() ? *it : nullptr;
}

ValueConfigNode::ValueConfigNode(BaseConfigNode* parent_node, const Value& val,
    const std::string& name) :
        BaseConfigNode(parent_node), value(val), custom_name(name)
{}

void ValueConfigNode::set_value(const snort::Value& v)
{
    if ( value.get_param_type() == Parameter::PT_MULTI )
    {
        std::string origin = value.get_origin_string();
        if ( !multi_value && value.has_default() )
            origin.clear();

        origin += " ";
        origin += v.get_origin_string();
        value.set_origin(origin.c_str());
        multi_value = true;
    }
    else
        value = v;
}

BaseConfigNode* ValueConfigNode::get_node(const std::string& name)
{
    if ( !custom_name.empty() )
        return ((custom_name == name) and value.has_default()) ? this : nullptr;
    else
        return value.is(name.c_str()) and value.has_default() ? this : nullptr;
}

ConfigData::ConfigData(const char* file)
{
    if ( file )
        file_name = file;
}

void ConfigData::sort()
{
    config_trees.sort([](const BaseConfigNode* l, const BaseConfigNode* r)
        { return l->get_name() < r->get_name(); });

    for ( auto config_tree : config_trees )
        BaseConfigNode::sort_nodes(config_tree);
}

void ConfigData::clear()
{
    for ( auto config_tree : config_trees )
        BaseConfigNode::clear_nodes(config_tree);

    config_trees.clear();
}

#ifdef UNIT_TEST
#include <catch/snort_catch.h>

TEST_CASE("add_nodes", "[ConfigData]")
{
    ConfigData config_data("test_file");

    auto node_test1 = new TreeConfigNode(nullptr, "test1", Parameter::Type::PT_TABLE);
    auto node_test2 = new TreeConfigNode(nullptr, "test2", Parameter::Type::PT_TABLE);

    config_data.add_config_tree(node_test1);
    config_data.add_config_tree(node_test2);

    CHECK(config_data.config_trees.size() == 2);

    config_data.clear();
}

TEST_CASE("clear_nodes", "[ConfigData]")
{
    ConfigData config_data("test_file");

    auto node_test1 = new TreeConfigNode(nullptr, "test1", Parameter::Type::PT_TABLE);
    auto node_test2 = new TreeConfigNode(nullptr, "test2", Parameter::Type::PT_TABLE);

    config_data.add_config_tree(node_test1);
    config_data.add_config_tree(node_test2);

    config_data.clear();

    CHECK(config_data.config_trees.size() == 0);
}

TEST_CASE("sort_nodes", "[ConfigData]")
{
    ConfigData config_data("test_file");

    auto node_test1 = new TreeConfigNode(nullptr, "test1", Parameter::Type::PT_TABLE);
    auto node_test2 = new TreeConfigNode(nullptr, "test2", Parameter::Type::PT_TABLE);
    auto node_test3 = new TreeConfigNode(nullptr, "test3", Parameter::Type::PT_TABLE);
    auto node_test4 = new TreeConfigNode(nullptr, "test4", Parameter::Type::PT_TABLE);

    config_data.add_config_tree(node_test2);
    config_data.add_config_tree(node_test3);
    config_data.add_config_tree(node_test4);
    config_data.add_config_tree(node_test1);

    CHECK(config_data.config_trees.front()->get_name() == "test2");
    CHECK(config_data.config_trees.back()->get_name() == "test1");

    config_data.sort();

    CHECK(config_data.config_trees.front()->get_name() == "test1");
    CHECK(config_data.config_trees.back()->get_name() == "test4");

    config_data.clear();
}

TEST_CASE("tree_config_node", "[TreeConfigNode]")
{
    BaseConfigNode* parent_node = new TreeConfigNode(nullptr, "parent_node",
        Parameter::Type::PT_TABLE);
    BaseConfigNode* child_node = new TreeConfigNode(parent_node, "child_node",
        Parameter::Type::PT_LIST);

    parent_node->add_child_node(child_node);

    SECTION("get_name")
    {
        CHECK(parent_node->get_name() == "parent_node");
        CHECK(child_node->get_name() == "child_node");
    }
    SECTION("get_type")
    {
        CHECK(parent_node->get_type() == Parameter::Type::PT_TABLE);
        CHECK(child_node->get_type() == Parameter::Type::PT_LIST);
    }
    SECTION("get_node")
    {
        CHECK(parent_node->get_node("child_node") == child_node);
        CHECK(parent_node->get_node("other_node") == nullptr);
        CHECK(child_node->get_node("child_node") == nullptr);
    }
    SECTION("get_parent_node")
    {
        CHECK(child_node->get_parent_node() == parent_node);
        CHECK(parent_node->get_parent_node() == nullptr);
    }
    SECTION("get_children")
    {
        CHECK(parent_node->get_children().size() == 1);
        CHECK(child_node->get_children().size() == 0);
    }
    SECTION("get_value")
    {
        CHECK(parent_node->get_value() == nullptr);
        CHECK(child_node->get_value() == nullptr);
    }

    BaseConfigNode::clear_nodes(parent_node);
}

TEST_CASE("value_config_node", "[ValueConfigNode]")
{
    BaseConfigNode* parent_node = new TreeConfigNode(nullptr, "parent_node",
        Parameter::Type::PT_TABLE);

    const Parameter p_string("param_str", Parameter::PT_STRING, nullptr, nullptr,
        "test param PT_STRING type");

    const Parameter p_string_custom("param_str_custom", Parameter::PT_STRING, nullptr,
        "custom_default", "test param PT_STRING type with custom name");

    const Parameter p_bool_w_default("param_bool", Parameter::PT_BOOL, nullptr, "false",
        "test param PT_BOOL type with default");

    const Parameter p_multi_w_default("param_multi", Parameter::PT_MULTI,
        "test1 | test2 | test3 | test4", "test2 test3", "test param PT_MULTI type with default");

    Value val_str("test_str");
    val_str.set(&p_string);

    Value val_str_custom("test_str_custom");
    val_str_custom.set(&p_string_custom);

    Value val_bool(true);
    val_bool.set(&p_bool_w_default);

    Value val_multi("test2 test3");
    val_multi.set(&p_multi_w_default);

    BaseConfigNode* value_node_str = new ValueConfigNode(parent_node, val_str);
    BaseConfigNode* value_node_bool = new ValueConfigNode(parent_node, val_bool);
    BaseConfigNode* value_node_multi = new ValueConfigNode(parent_node, val_multi);
    BaseConfigNode* value_node_custom_name = new ValueConfigNode(parent_node, val_str_custom,
        "custom_name");

    parent_node->add_child_node(value_node_str);
    parent_node->add_child_node(value_node_bool);
    parent_node->add_child_node(value_node_multi);
    parent_node->add_child_node(value_node_custom_name);

    SECTION("get_name")
    {
        CHECK(value_node_str->get_name() == "param_str");
        CHECK(value_node_bool->get_name() == "param_bool");
        CHECK(value_node_multi->get_name() == "param_multi");
        CHECK(value_node_custom_name->get_name() == "custom_name");
    }
    SECTION("get_type")
    {
        CHECK(value_node_str->get_type() == Parameter::PT_STRING);
        CHECK(value_node_bool->get_type() == Parameter::PT_BOOL);
        CHECK(value_node_multi->get_type() == Parameter::PT_MULTI);
        CHECK(value_node_custom_name->get_type() == Parameter::PT_STRING);
    }
    SECTION("get_node")
    {
        CHECK(parent_node->get_node("param_str") == value_node_str);
        CHECK(parent_node->get_node("param_bool") == value_node_bool);
        CHECK(parent_node->get_node("param_multi") == value_node_multi);
        CHECK(parent_node->get_node("custom_name") == value_node_custom_name);

        CHECK(value_node_str->get_node("param_str") == nullptr);
        CHECK(value_node_bool->get_node("param_bool") == value_node_bool);
        CHECK(value_node_multi->get_node("param_multi") == value_node_multi);
        CHECK(value_node_custom_name->get_node("custom_name") == value_node_custom_name);
    }
    SECTION("get_parent_node")
    {
        CHECK(value_node_str->get_parent_node() == parent_node);
        CHECK(value_node_bool->get_parent_node() == parent_node);
        CHECK(value_node_multi->get_parent_node() == parent_node);
        CHECK(value_node_custom_name->get_parent_node() == parent_node);
    }
    SECTION("get_children")
    {
        CHECK(parent_node->get_children().size() == 4);
        CHECK(value_node_multi->get_children().size() == 0);
        CHECK(value_node_str->get_children().size() == 0);
        CHECK(value_node_bool->get_children().size() == 0);
        CHECK(value_node_custom_name->get_children().size() == 0);
    }
    SECTION("get_value")
    {
        CHECK(value_node_str->get_value()->get_origin_string() == "test_str");
        CHECK(true == value_node_bool->get_value()->get_bool());
        CHECK(value_node_multi->get_value()->get_origin_string() == "test2 test3");
        CHECK(value_node_custom_name->get_value()->get_origin_string() == "test_str_custom");
    }

    Value new_val_str("new_value");
    value_node_str->set_value(new_val_str);

    Value new_custom_val_str("new_custom_value");
    value_node_custom_name->set_value(new_custom_val_str);

    Value new_val_bool(false);
    value_node_bool->set_value(new_val_bool);

    Value new_val1_multi("test1");
    value_node_multi->set_value(new_val1_multi);

    Value new_val2_multi("test2");
    value_node_multi->set_value(new_val2_multi);

    Value new_val3_multi("test3");
    value_node_multi->set_value(new_val3_multi);

    SECTION("get_value_after_update")
    {
        CHECK(value_node_str->get_value()->get_origin_string() == "new_value");
        CHECK(false == value_node_bool->get_value()->get_bool());
        CHECK(value_node_multi->get_value()->get_origin_string() == "test1 test2 test3");
        CHECK(value_node_custom_name->get_value()->get_origin_string() == "new_custom_value");
    }

    BaseConfigNode::clear_nodes(parent_node);
}

#endif

