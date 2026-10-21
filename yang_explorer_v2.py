The file write needs your approval. Once you grant it, the script will be saved to `/opt/NetAutoCommitter/020_yang_datastore_diff.py`.

The script is a **YANG datastore diff tool** — it fetches the same YANG subtree from two different RESTCONF datastores (e.g., running vs startup) and shows:
- Keys that changed value between the two datastores
- Keys only present in the source (removed in target)
- Keys only present in the target (added vs source)

This is practical for post-maintenance audits confirming `write memory` was run, or spotting uncommitted candidate config. It avoids all functionality in the existing 001–019 scripts (which cover discovery, ACL, VLAN, BGP, OSPF, interface config, SNMP, routing, and bulk ops).