# Security Gateway - CSC 262

**Author:** Urooj Fatima  
**Course:** AI PROJECT
<br>
**University:** COMSATS University Islamabad, Wah Campus  

---

## 📝 Project Overview
This project is a **Secure Gateway** designed to prevent **prompt injection, jailbreak attacks**, and **PII leaks** using FastAPI and Presidio.  
The project implements a **scoring mechanism** to detect malicious inputs and applies policies to **allow, mask, or block** sensitive content.

---

## ⚙️ Features
- FastAPI backend for API requests  
- Prompt Injection & Jailbreak scoring (`injection_score()` function)  
- PII detection & anonymization using **Presidio**  
- **Custom recognizers**:
  1. API Key Recognizer  
  2. Internal ID Recognizer  
  3. Phone Number Recognizer  
- Configurable thresholds & context-aware scoring  
- Latency measurement for each request  
- Modular code: `main.py` + `detectors.py`  
- Fully documented & reproducible via GitHub  

make folder 
download all filesa and placae in a common folder 
then run the main.py file just all others are helping file
