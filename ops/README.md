Operational enablement files are not stored in git.

Read-only production verification (does not dispatch or write):

```
PYTHONPATH=src python3 -m silastron_pulse verify-operations
```

If GitHub authentication is unavailable, run the printed `owner_commands`
locally. Do not dispatch Collect, Publish, or Deploy as part of that check.

EPSS publication remains blocked until the repository owner records a
written redistribution determination and a reviewed code change flips
`REDISTRIBUTION_CLEARED` in `src/silastron_pulse/adapters/epss.py`.
