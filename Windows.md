
# 🪟 Operating System & Scripting (Windows) — Cheatsheet

## 📁 File & Directory Management

| Command    | Full Meaning             | কেন ব্যবহার হয়                          | বাস্তব Example                               |
| ---------- | ------------------------ | --------------------------------------- | -------------------------------------------- |
| `dir`      | **Directory Listing**    | একটি ফোল্ডারে কি ফাইল/ফোল্ডার আছে দেখতে | `dir C:\Users\Public`                        |
| `cd`       | **Change Directory**     | ফোল্ডারের মধ্যে যেতে                    | `cd C:\Windows\System32`                     |
| `copy`     | **Copy File**            | ফাইল এক জায়গা থেকে অন্য জায়গায় কপি করতে | `copy C:\Users\Admin\file.txt D:\backup\`    |
| `xcopy`    | **Extended Copy**        | ডিরেক্টরি ও সাব-ডিরেক্টরি কপি করতে      | `xcopy C:\Data D:\Backup /E /I`              |
| `robocopy` | **Robust File Copy**     | বড় ডিরেক্টরি দ্রুত কপি করতে             | `robocopy C:\Data D:\Backup /MIR`            |
| `del`      | **Delete File**          | ফাইল ডিলিট করতে                         | `del C:\Windows\Temp\log.txt`                |
| `attrib`   | **File Attributes**      | ফাইলকে Hidden, Read-only করতে           | `attrib +h secret.txt`                       |
| `type`     | **Display File Content** | ফাইলের কনটেন্ট দেখতে                    | `type C:\Windows\System32\drivers\etc\hosts` |

---

## 👤 User & Permission Management

| Command          | Full Meaning                 | কেন ব্যবহার হয়                         | বাস্তব Example                              |
| ---------------- | ---------------------------- | -------------------------------------- | ------------------------------------------- |
| `net user`       | **Network User Management**  | সব ইউজার দেখতে বা ইউজার তৈরি করতে      | `net user hacker P@ssw0rd! /add`            |
| `net localgroup` | **Local Group Management**   | ইউজারকে গ্রুপে অ্যাড করতে              | `net localgroup administrators hacker /add` |
| `whoami`         | **Who Am I**                 | বর্তমান লগইনকৃত ইউজার জানতে            | `whoami`                                    |
| `whoami /priv`   | **Who Am I with Privileges** | ইউজারের privilege দেখতে                | `whoami /priv`                              |
| `runas`          | **Run As Another User**      | অন্য ইউজারের privilege এ কমান্ড চালাতে | `runas /user:Administrator cmd`             |
| `net accounts`   | **Password Policy**          | পাসওয়ার্ড পলিসি চেক করতে               | `net accounts`                              |

---

## 🌐 Networking & Reconnaissance

| Command     | Full Meaning                        | কেন ব্যবহার হয়                         | বাস্তব Example                                         |
| ----------- | ----------------------------------- | -------------------------------------- | ------------------------------------------------------ |
| `ipconfig`  | **Internet Protocol Configuration** | IP, Gateway, DNS তথ্য জানতে            | `ipconfig /all`                                        |
| `ping`      | **Packet Internet Groper**          | সার্ভার alive কিনা চেক করতে            | `ping google.com`                                      |
| `tracert`   | **Trace Route**                     | নেটওয়ার্ক পথ ট্রেস করতে                | `tracert google.com`                                   |
| `nslookup`  | **Name Server Lookup**              | DNS রেকর্ড চেক করতে                    | `nslookup example.com`                                 |
| `arp -a`    | **Address Resolution Protocol**     | লোকাল নেটওয়ার্কের IP ↔ MAC ম্যাপ দেখতে | `arp -a`                                               |
| `netstat`   | **Network Statistics**              | খোলা পোর্ট ও কানেকশন দেখতে             | `netstat -ano`                                         |
| `net view`  | **Network View**                    | শেয়ারড কম্পিউটার দেখতে                 | `net view \\192.168.1.10`                              |
| `net share` | **Network Share**                   | শেয়ারড ফোল্ডার দেখতে                   | `net share`                                            |
| `net use`   | **Network Use**                     | নেটওয়ার্ক drive মাউন্ট করতে            | `net use Z: \\192.168.1.10\share /user:admin P@ssw0rd` |

---

## ⚙️ Process & Service Management

| Command       | Full Meaning              | কেন ব্যবহার হয়                     | বাস্তব Example          |
| ------------- | ------------------------- | ---------------------------------- | ----------------------- |
| `tasklist`    | **Task List**             | চলমান প্রসেস দেখতে                 | `tasklist`              |
| `taskkill`    | **Task Kill**             | প্রসেস বন্ধ করতে                   | `taskkill /PID 1234 /F` |
| `sc query`    | **Service Control Query** | সার্ভিস লিস্ট দেখতে                | `sc query`              |
| `net start`   | **Network Start**         | কোন সার্ভিস চলছে তা দেখতে          | `net start`             |
| `net stop`    | **Network Stop**          | কোন সার্ভিস বন্ধ করতে              | `net stop Spooler`      |
| `systeminfo`  | **System Information**    | OS, হার্ডওয়্যার, প্যাচ লেভেল দেখতে | `systeminfo`            |
| `hostname`    | **Host Name**             | কম্পিউটারের নাম দেখতে              | `hostname`              |
| `driverquery` | **Driver Query**          | ইনস্টলড ড্রাইভার দেখতে             | `driverquery`           |
| `quser`       | **Query User**            | লগইনকৃত ইউজার দেখতে                | `quser`                 |

---

## 🔑 Registry & Logs (Forensics)

| Command     | Full Meaning                       | কেন ব্যবহার হয়                 | বাস্তব Example                                                 |
| ----------- | ---------------------------------- | ------------------------------ | -------------------------------------------------------------- |
| `reg query` | **Registry Query**                 | Registry key দেখতে             | `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run` |
| `eventvwr`  | **Event Viewer**                   | Windows Event Viewer ওপেন করতে | `eventvwr`                                                     |
| `wevtutil`  | **Windows Event Utility**          | লগ দেখা/ডিলিট করতে             | `wevtutil qe System /c:10 /rd:true`                            |
| `cipher`    | **Encrypt/Decrypt Files**          | ফাইল এনক্রিপ্ট/ডিক্রিপ্ট করতে  | `cipher /E C:\Secret`                                          |
| `icacls`    | **Integrity Control Access Lists** | ফাইল পারমিশন চেক/পরিবর্তন করতে | `icacls C:\Secret`                                             |
| `fsutil`    | **File System Utility**            | ডিস্ক ও ফাইল সিস্টেম ইনফো পেতে | `fsutil fsinfo drives`                                         |

---

## 📦 File Transfer & PowerShell Basics

| Command             | Full Meaning               | কেন ব্যবহার হয়              | বাস্তব Example                                                                       |
| ------------------- | -------------------------- | --------------------------- | ------------------------------------------------------------------------------------ |
| `powershell`        | **Windows PowerShell**     | উন্নত স্ক্রিপ্টিং ও অটোমেশন | `powershell Get-Process`                                                             |
| `Invoke-WebRequest` | **PowerShell Web Request** | ফাইল ডাউনলোড করতে           | `powershell Invoke-WebRequest -Uri http://example.com/file.exe -OutFile C:\file.exe` |
| `Get-Content`       | **Read File Content**      | ফাইল কনটেন্ট পড়তে           | `powershell Get-Content C:\Windows\System32\drivers\etc\hosts`                       |
| `Get-Process`       | **Process List**           | প্রসেস দেখতে                | `powershell Get-Process`                                                             |
| `Get-Service`       | **Service List**           | সার্ভিস দেখতে               | `powershell Get-Service`                                                             |
| `Get-NetIPAddress`  | **Network IP Info**        | নেটওয়ার্ক ইনফো পেতে         | `powershell Get-NetIPAddress`                                                        |
