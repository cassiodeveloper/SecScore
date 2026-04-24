<!-- SECSCORE_COMMENT -->
## 🟡 SecScore — **REVIEW**

Security score: **84/100**

🟡 Security review recommended.

New vulnerabilities introduced: **4 Medium**

---
### Why this decision
- Potential path traversal risk
- SQL query built using user input
- Unvalidated redirect

---
### Security Diff
🔴 Critical: 0  
🟠 High: 0  
🟡 Medium: +4  
🟢 Low: 0  

---
### Findings introduced in this PR
- **MEDIUM** — Potential path traversal risk  
  [`src/controllers/fileController.js:34`](./src/controllers/fileController.js#L34)
- **MEDIUM** — SQL query built using user input  
  [`src/db/userRepository.js:52`](./src/db/userRepository.js#L52)
- **MEDIUM** — Unvalidated redirect  
  [`src/controllers/authController.js:88`](./src/controllers/authController.js#L88)
- **MEDIUM** — Unvalidated redirect  
  [`src/controllers/dbController.js:88`](./src/controllers/dbController.js#L88)

---
SecScore — Security scoring that matters.