# Ruleset fetch and merge automation

This repo contains a script to fetch rules from https://ruleset.skk.moe/, remove unneeded entries, merge selected rule groups, and produce output files for Surge and Quantumult X.

Usage

- Install deps:
```
pip install -r requirements.txt
```
- Run the processor:
```
python3 scripts/process_rules.py
```

Outputs are written to the `generated/` directory.

CI

The workflow `.github/workflows/weekly.yml` runs weekly and commits updated generated files back to the repo.
