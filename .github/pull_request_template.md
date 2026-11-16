## Summary of changes
<!-- What does this pull request change and why? -->

## AI-use disclosure (required)
- [ ] No AI tools were used for this change
- [ ] AI tools were used (complete the section below)

| Item | Details |
|---|---|
| AI tool and version | <!-- e.g., GitHub Copilot, ChatGPT --> |
| What the AI helped with | <!-- e.g., generated the login query function --> |
| Files affected | <!-- list files containing AI-generated or AI-modified code --> |
| Corrections made after generation | <!-- what you changed in the AI output --> |

## Security review rubric (Table 1)
Rate each metric: **Critically Flawed / Revision Needed / Deployment Ready**

| Metric | Rating | Notes |
|---|---|---|
| Hard-coded Secret Protection | | |
| Dependency & Supply Chain Safety | | |
| Injection Defense | | |
| Input Sanitization & Validation | | |
| Access Control & Authorization | | |

A pull request can be merged only when every metric is **Deployment Ready**.

## Testing completed
- [ ] Stage I – Scan: Semgrep and Bandit pass (no blocking findings)
- [ ] Stage II – Test: security tests pass, including malicious input
- [ ] New dependencies verified to exist on the official registry, be maintained, and have no known CVEs
- [ ] No passwords, customer data, or confidential code were shared with the AI tool

## Reviewer sign-off (Stage III)
- [ ] All findings are documented and every fix matches a finding
- [ ] AI-generated changes do not introduce risks in other parts of the application
