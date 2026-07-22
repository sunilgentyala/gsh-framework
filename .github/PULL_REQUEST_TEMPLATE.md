<!--
PR title format (see CONTRIBUTING.md section 7):
[playbook] Add Hunt-006: Agent Memory Poisoning
[fix] Hunt-002: Reduce CDN false positive rate for Fastly domains
[adapter] Add AutoGen callback hook for ZTLV gate integration
[docs] Clarify baseline window requirements in Hunt-003
-->

**Closes #** <!-- issue number this PR addresses -->

**What does this change and why**


**Testing performed**
<!-- `python -m pytest tests/ -v` output, or for playbooks: the test environment used to
     validate detection thresholds -->

**Checklist**
- [ ] Branch is up to date with `main`
- [ ] `python -m pytest tests/ -v` passes locally
- [ ] `python -m ruff check .` passes locally
- [ ] New detection logic includes at least one positive and one negative test case (CONTRIBUTING.md section 6)
- [ ] Threshold changes (if any) include written justification with supporting data or references
- [ ] No hardcoded credentials, API keys, or organization-specific values
