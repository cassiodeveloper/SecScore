<!-- SECSCORE_COMMENT -->
## ⛔ SecScore — **FAIL**

Security score: **85/100**

⛔ Merge **blocked** by security policy: `policy\policy-pr.yml`

New vulnerabilities introduced: **1 High, 1 Medium**

---
### Why this decision
- New critical / high SAST finding(s).

---
### Security Diff
🔴 Critical: 0  
🟠 High: +1  
🟡 Medium: +1  
🟢 Low: 0  

---
### Findings introduced in this PR
- **HIGH** — User input flows into HTML response without proper encoding  
  [`src/controllers/userController.js:27`](./src/controllers/userController.js#L27)
- **MEDIUM** — SQL query constructed using unsanitized user input  
  [`src/db/userRepository.js:52`](./src/db/userRepository.js#L52)

---
SecScore — Security scoring that matters.