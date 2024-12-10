/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM ras
#define TRACE_INCLUDE_FILE ras_event

#if !defined(_TRACE_HW_EVENT_MC_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_HW_EVENT_MC_H

#include <linux/tracepoint.h>
#include <linux/edac.h>
#include <linux/ktime.h>
#include <linux/pci.h>
#include <linux/aer.h>
#include <linux/cper.h>
#include <linux/mm.h>

/*
 * MCE Extended Error Log trace event
 *
 * These events are generated when hardware detects a corrected or
 * uncorrected event.
 */

/* memory trace event */

#if defined(CONFIG_ACPI_EXTLOG) || defined(CONFIG_ACPI_EXTLOG_MODULE)
#endif

/*
 * Hardware Events Report
 *
 * Those events are generated when hardware detected a corrected or
 * uncorrected event, and are meant to replace the current API to report
 * errors defined on both EDAC and MCE subsystems.
 *
 * FIXME: Add events for handling memory errors originated from the
 *        MCE subsystem.
 */

/*
 * Hardware-independent Memory Controller specific events
 */

/*
 * Default error mechanisms for Memory Controller errors (CE and UE)
 */

/*
 * ARM Processor Events Report
 *
 * This event is generated when hardware detects an ARM processor error
 * has occurred. UEFI 2.6 spec section N.2.4.4.
 */

/*
 * Non-Standard Section Report
 *
 * This event is generated when hardware detected a hardware
 * error event, which may be of non-standard section as defined
 * in UEFI spec appendix "Common Platform Error Record", or may
 * be of sections for which TRACE_EVENT is not defined.
 *
 */

/*
 * PCIe AER Trace event
 *
 * These events are generated when hardware detects a corrected or
 * uncorrected event on a PCIe device. The event report has
 * the following structure:
 *
 * char * dev_name -	The name of the slot where the device resides
 *			([domain:]bus:device.function).
 * u32 status -		Either the correctable or uncorrectable register
 *			indicating what error or errors have been seen
 * u8 severity -	error severity 0:NONFATAL 1:FATAL 2:CORRECTED
 */

#define aer_correctable_errors					\
	{PCI_ERR_COR_RCVR,	"Receiver Error"},		\
	{PCI_ERR_COR_BAD_TLP,	"Bad TLP"},			\
	{PCI_ERR_COR_BAD_DLLP,	"Bad DLLP"},			\
	{PCI_ERR_COR_REP_ROLL,	"RELAY_NUM Rollover"},		\
	{PCI_ERR_COR_REP_TIMER,	"Replay Timer Timeout"},	\
	{PCI_ERR_COR_ADV_NFAT,	"Advisory Non-Fatal Error"},	\
	{PCI_ERR_COR_INTERNAL,	"Corrected Internal Error"},	\
	{PCI_ERR_COR_LOG_OVER,	"Header Log Overflow"}

#define aer_uncorrectable_errors				\
	{PCI_ERR_UNC_UND,	"Undefined"},			\
	{PCI_ERR_UNC_DLP,	"Data Link Protocol Error"},	\
	{PCI_ERR_UNC_SURPDN,	"Surprise Down Error"},		\
	{PCI_ERR_UNC_POISON_TLP,"Poisoned TLP"},		\
	{PCI_ERR_UNC_FCP,	"Flow Control Protocol Error"},	\
	{PCI_ERR_UNC_COMP_TIME,	"Completion Timeout"},		\
	{PCI_ERR_UNC_COMP_ABORT,"Completer Abort"},		\
	{PCI_ERR_UNC_UNX_COMP,	"Unexpected Completion"},	\
	{PCI_ERR_UNC_RX_OVER,	"Receiver Overflow"},		\
	{PCI_ERR_UNC_MALF_TLP,	"Malformed TLP"},		\
	{PCI_ERR_UNC_ECRC,	"ECRC Error"},			\
	{PCI_ERR_UNC_UNSUP,	"Unsupported Request Error"},	\
	{PCI_ERR_UNC_ACSV,	"ACS Violation"},		\
	{PCI_ERR_UNC_INTN,	"Uncorrectable Internal Error"},\
	{PCI_ERR_UNC_MCBTLP,	"MC Blocked TLP"},		\
	{PCI_ERR_UNC_ATOMEG,	"AtomicOp Egress Blocked"},	\
	{PCI_ERR_UNC_TLPPRE,	"TLP Prefix Blocked Error"}


/*
 * memory-failure recovery action result event
 *
 * unsigned long pfn -	Page Frame Number of the corrupted page
 * int type	-	Page types of the corrupted page
 * int result	-	Result of recovery action
 */

#ifdef CONFIG_MEMORY_FAILURE
#define MF_ACTION_RESULT	\
	EM ( MF_IGNORED, "Ignored" )	\
	EM ( MF_FAILED,  "Failed" )	\
	EM ( MF_DELAYED, "Delayed" )	\
	EMe ( MF_RECOVERED, "Recovered" )

#define MF_PAGE_TYPE		\
	EM ( MF_MSG_KERNEL, "reserved kernel page" )			\
	EM ( MF_MSG_KERNEL_HIGH_ORDER, "high-order kernel page" )	\
	EM ( MF_MSG_SLAB, "kernel slab page" )				\
	EM ( MF_MSG_DIFFERENT_COMPOUND, "different compound page after locking" ) \
	EM ( MF_MSG_POISONED_HUGE, "huge page already hardware poisoned" )	\
	EM ( MF_MSG_HUGE, "huge page" )					\
	EM ( MF_MSG_FREE_HUGE, "free huge page" )			\
	EM ( MF_MSG_NON_PMD_HUGE, "non-pmd-sized huge page" )		\
	EM ( MF_MSG_UNMAP_FAILED, "unmapping failed page" )		\
	EM ( MF_MSG_DIRTY_SWAPCACHE, "dirty swapcache page" )		\
	EM ( MF_MSG_CLEAN_SWAPCACHE, "clean swapcache page" )		\
	EM ( MF_MSG_DIRTY_MLOCKED_LRU, "dirty mlocked LRU page" )	\
	EM ( MF_MSG_CLEAN_MLOCKED_LRU, "clean mlocked LRU page" )	\
	EM ( MF_MSG_DIRTY_UNEVICTABLE_LRU, "dirty unevictable LRU page" )	\
	EM ( MF_MSG_CLEAN_UNEVICTABLE_LRU, "clean unevictable LRU page" )	\
	EM ( MF_MSG_DIRTY_LRU, "dirty LRU page" )			\
	EM ( MF_MSG_CLEAN_LRU, "clean LRU page" )			\
	EM ( MF_MSG_TRUNCATED_LRU, "already truncated LRU page" )	\
	EM ( MF_MSG_BUDDY, "free buddy page" )				\
	EM ( MF_MSG_BUDDY_2ND, "free buddy page (2nd try)" )		\
	EM ( MF_MSG_DAX, "dax page" )					\
	EM ( MF_MSG_UNSPLIT_THP, "unsplit thp" )			\
	EMe ( MF_MSG_UNKNOWN, "unknown page" )

/*
 * First define the enums in MM_ACTION_RESULT to be exported to userspace
 * via TRACE_DEFINE_ENUM().
 */
#undef EM
#undef EMe
#define EM(a, b) TRACE_DEFINE_ENUM(a);
#define EMe(a, b)	TRACE_DEFINE_ENUM(a);

MF_ACTION_RESULT
MF_PAGE_TYPE

/*
 * Now redefine the EM() and EMe() macros to map the enums to the strings
 * that will be printed in the output.
 */
#undef EM
#undef EMe
#define EM(a, b)		{ a, b },
#define EMe(a, b)	{ a, b }

#endif /* CONFIG_MEMORY_FAILURE */
#endif /* _TRACE_HW_EVENT_MC_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
