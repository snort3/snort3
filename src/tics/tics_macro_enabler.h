#ifndef __TICS_MACRO_ENABLER_H__
#define __TICS_MACRO_ENABLER_H__

/* Enable dpdk based load balance daq */
#if 0
#define TICS_USE_LOAD_BALANCE
#endif /* 0 */

#if 1
#define TICS_STATIC_HASH /* Make sure the rule file stays the same every time */
#endif /* 0 */

/* TICS rule file generation functionality enabler */
#if 1
#define TICS_GENERATE_RULE_FILE
#endif /* 0 */

/* TICS matching engine enabler*/
#if 1
#define TICS_USE_RXP_MATCH //ENABLE RXP matching engine
#endif /* 0 */

#ifdef TICS_USE_RXP_MATCH
#ifndef TICS_GENERATE_RULE_FILE
#define TICS_GENERATE_RULE_FILE
#endif /* !TICS_GENERATE_RULE_FILE */
#endif /* TICS_USE_RXP_MATCH */

#ifdef TICS_GENERATE_RULE_FILE
#ifndef TICS_STATIC_HASH
#define TICS_STATIC_HASH /* Make sure the rule file stays the same every time */
#endif /* !TICS_STATIC_HASH */
#endif /* TICS_GENERATE_RULE_FILE */

#if defined (TICS_USE_RXP_MATCH) && defined (TICS_GENERATE_RULE_FILE)
#if 1 //Enable HYPERSCAN_RXP_HYBRID matching engine if not define then RXP ONLY
#define TICS_USE_HYPERSCAN_RXP_HYBRID_MATCH //HYPERSCAN_RXP_HYBRID matching engine
#endif /* 0 */
#endif /* TICS_USE_RXP_MATCH && TICS_GENERATE_RULE_FILE*/

#endif /* __TICS_MACRO_ENABLER_H__ */
