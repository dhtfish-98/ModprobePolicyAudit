# ModprobePolicyAudit

Module policy aliases, dependencies and disablement audit. Complete independent **new scope**, not the whole upstream system rewritten.

Input: `{"files":{"/etc/modprobe.d/99-policy.conf":"blacklist old-fs\ninstall old_fs /bin/false"},"disabled_modules":["old-fs"],"loaded_modules":[]}`. Five default modprobe.d directory priorities and lexical file order are resolved; hyphens/underscores normalize. All seven documented command forms are parsed: alias, blacklist, install, remove, options, softdep, weakdep. Checks cover global/disabled-target/alias-chain redirects, exact blocking stubs, contradictory options, dependency cycles/depth/budget, softdep override precedence and supplied loaded-module state. Blacklist alone FAILs a declared disablement goal because it does not block direct module load. Even a PASS only demonstrates declared modprobe policy; direct privileged loading, built-ins, initramfs and module-provided aliases remain OPEN. Arbitrary shell overrides and module-specific option meanings are OPEN and never executed. Disablement targets are caller policy, not an official list of universally unsafe modules.

## Use and output

Install `artifacts/*.whl` and run `modprobe-policy-audit examples/good.json`, or `python -m modprobe_policy_audit examples/good.json`. JSON findings have PASS/FAIL/OPEN, evidence, explanation and counts. Exit codes: PASS 0, FAIL 1, ERROR 2, OPEN 3. Incomplete/unsupported evidence cannot produce exit 0. Input: regular non-symlink unchanged file, 2 MiB maximum, 32 JSON layers, 100000 nodes, no duplicate keys/nonfinite values; findings cap 20000. Each project is independently packaged with no external runtime dependency.

## Verification and limits

Read `ORIGIN.md`, `NOTICE` where present, `tests/`, `examples/expectations.json`, `VALIDATION.md` and exact `artifacts/validation.json`. Tests use public frozen policy data or synthetic fixtures only. Local parser/policy/wheel/CLI results are separate from real Linux/Windows execution, effective security, upstream equivalence and CVP eligibility/approval, which remain OPEN. No live host collection, code execution, configuration change or network action occurs.
