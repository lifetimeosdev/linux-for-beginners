/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BEN_VLAN_PROC_INC__
#define __BEN_VLAN_PROC_INC__

struct net;

int vlan_proc_init(struct net *net);
void vlan_proc_rem_dev(struct net_device *vlandev);
int vlan_proc_add_dev(struct net_device *vlandev);
void vlan_proc_cleanup(struct net *net);

#endif /* !(__BEN_VLAN_PROC_INC__) */
