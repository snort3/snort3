/*
 *   sfrim.h    
 *
 *   Rule Index Map
 *   
 *   author: marc norton
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 *   Copyright (C) 2005-2013 Sourcefire, Inc.
 */
#ifndef SFRIM_H
#define SFRIM_H

typedef struct {
     unsigned gid;
     unsigned sid;
}rule_number_t;

typedef struct {
    int  max_rules;
    int  num_rules;
    rule_number_t * map;
}rule_index_map_t;

unsigned RuleIndexMapSid( rule_index_map_t * map, int index );
unsigned RuleIndexMapGid( rule_index_map_t * map, int index );
rule_index_map_t * RuleIndexMapCreate( int max_rules );
void RuleIndexMapFree( rule_index_map_t ** p );
int RuleIndexMapAdd( rule_index_map_t * p, unsigned gid, unsigned sid );

#endif
