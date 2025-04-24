# PersistoX

🔐 **Python-based Windows Persistence Scanner for Red Teamers and Penetration testers**

**Author:** Ibrahim Ali (0xRobinHo0d) — [@ibraheemmajzoup](https://x.com/ibraheemmajzoup)    
**Platform:** Windows  
**Version:** 1.0  
**License:** MIT

---

## 🧠 About

**Persistox** is a Python-based Windows persistence scanning tool I've been working on. It's designed for red teamers and penetration testers, automating the discovery of Windows persistence mechanisms across a target system. Persistox helps uncover and detect potential persistence vectors.

> The goal: Quickly identify persistence vectors that can be exploited **under the current user context**, including checking for write permissions and the needed checks to perform the persistence also the required instructions for the command-line usage.

---

## 🛠 Supported Persistence Techniques

- Account Creation  
- Startup Folders 
- Registry Autoruns (Run/RunOnce)  
- Winlogon Scripts  
- File Association Hijacking  
- Shortcut Modification  
- PowerShell Profile  
- Scheduled Tasks  
- Windows Services  
- DLL Hijacking  
- COM Hijacking / Proxying  
- Accessibility Binaries  
- BITSAdmin Jobs  
- Netsh Helper DLL  
- Application Shimming  
- WMI Event Subscription  
- IFEO & AppInit/AppCert DLLs  
- Time Provider DLLs  
- Screensaver Replacement  
- Print-related DLLs  
- LSA-loaded DLLs  
- Developer Hooks
---

## ✨ Key Features

- ✅ **Writable Check:** Verifies if the current user has write access to registry keys or file paths.
- ✅ **Native Tool Scanning:** Uses `schtasks`, `sc`, `bitsadmin`, `wmic`, and `sdbinst` and other windows native tools to find persistence vectors.
- ✅ **Actionable Output:** Shows whether the method can be used and provides usage commands and instructions on how to leverage it.
- ✅ **Technique Descriptions:** Each persistence method includes a short description .

---

## ⚙️ Installation

```bash
git clone https://github.com/0xRobinHo0d/Persistox.git
cd Persistox
pip install -r requirements.txt
