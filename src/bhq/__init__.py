"""bhq — offline BloodHound JSON analyzer.

Answers the recurring AD-analysis questions from raw SharpHound / bloodhound-python /
bloodhound-ce-python JSON, without standing up neo4j + the BloodHound GUI:

  1. what can I crack offline?        -> kerberoastable / asreproastable
  2. what do I (or my groups) control? -> ACL outbound edges, path to admin-equivalence
  3. where am I local admin / remote?  -> AdminTo / CanRDP / CanPSRemote (if collected)
  4. any special high-value rights?    -> delegation, DCSync
  5. who can reach high value?         -> one reverse graph traversal

The graph engine lives in `loader`, the analysis functions in `queries`, the
human-readable report in `report`, and the CLI in `cli`.
"""

__version__ = "0.1.1"
