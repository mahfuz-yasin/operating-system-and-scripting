
# 🐧 Operating System & Scripting (Linux) — Extended Cheatsheet


## 👤 User & Account Management

| Command   | Full Meaning             | কেন ব্যবহার হয়                  | বাস্তব Example                 |
| --------- | ------------------------ | ------------------------------- | ------------------------------ |
| `adduser` | **Add User**             | নতুন ইউজার তৈরি করতে            | `sudo adduser hacker`          |
| `userdel` | **Delete User**          | ইউজার রিমুভ করতে                | `sudo userdel hacker`          |
| `usermod` | **User Modify**          | ইউজারকে নতুন গ্রুপে অ্যাড করতে  | `sudo usermod -aG sudo hacker` |
| `passwd`  | **Change Password**      | ইউজারের পাসওয়ার্ড পরিবর্তন করতে | `passwd hacker`                |
| `groups`  | **Show Groups**          | ইউজার কোন গ্রুপে আছে দেখতে      | `groups hacker`                |
| `who`     | **Show Logged-in Users** | কে লগইন করেছে দেখতে             | `who`                          |

---

## 🔒 Advanced Permissions

| Command  | Full Meaning          | কেন ব্যবহার হয়                                     | বাস্তব Example         |
| -------- | --------------------- | -------------------------------------------------- | ---------------------- |
| `umask`  | **User Mask**         | নতুন ফাইল/ডিরেক্টরির ডিফল্ট পারমিশন নিয়ন্ত্রণ করতে | `umask 022`            |
| `stat`   | **File Status**       | ফাইলের ডিটেইলস দেখতে (size, inode, modify time)    | `stat /etc/passwd`     |
| `lsattr` | **List Attributes**   | ফাইল অ্যাট্রিবিউট দেখতে (immutable files)          | `lsattr /etc/passwd`   |
| `chattr` | **Change Attributes** | ফাইলকে immutable বা append-only বানাতে             | `chattr +i secret.txt` |

---

## 📊 System Monitoring & Diagnostics

| Command  | Full Meaning                  | কেন ব্যবহার হয়              | বাস্তব Example         |
| -------- | ----------------------------- | --------------------------- | ---------------------- |
| `free`   | **Free Memory**               | RAM ও Swap ব্যবহার চেক করতে | `free -h`              |
| `vmstat` | **Virtual Memory Statistics** | CPU, Memory, IO usage দেখতে | `vmstat 2`             |
| `iostat` | **Input/Output Statistics**   | ডিস্ক IO চেক করতে           | `iostat -xz 2`         |
| `uptime` | **System Uptime**             | সিস্টেম কতক্ষণ অন আছে দেখতে | `uptime`               |
| `lsblk`  | **List Block Devices**        | ডিস্ক পার্টিশন দেখতে        | `lsblk`                |
| `mount`  | **Mount Filesystem**          | ডিস্ক বা ড্রাইভ মাউন্ট করতে | `mount /dev/sdb1 /mnt` |
| `umount` | **Unmount Filesystem**        | মাউন্ট আনমাউন্ট করতে        | `umount /mnt`          |
| `df`     | **Disk Free Space**           | ডিস্ক স্পেস চেক করতে        | `df -h`                |
| `du`     | **Disk Usage**                | ফোল্ডারের সাইজ দেখতে        | `du -sh /var/log`      |

---

## 🌐 Advanced Networking

| Command      | Full Meaning                    | কেন ব্যবহার হয়                       | বাস্তব Example                     |
| ------------ | ------------------------------- | ------------------------------------ | ---------------------------------- |
| `curl`       | **Client URL**                  | ওয়েব কনটেন্ট ডাউনলোড করতে            | `curl http://example.com`          |
| `wget`       | **Web Get**                     | ওয়েব থেকে ফাইল আনার জন্য             | `wget http://example.com/file.zip` |
| `nc`         | **Netcat**                      | পোর্ট স্ক্যান ও ব্যাকডোর তৈরি করতে   | `nc -lvnp 4444`                    |
| `telnet`     | **Telecommunication Network**   | রিমোট সার্ভারে কানেক্ট করতে          | `telnet 192.168.1.1 80`            |
| `dig`        | **Domain Information Groper**   | DNS ইনফো পেতে                        | `dig example.com MX`               |
| `nslookup`   | **Name Server Lookup**          | DNS রেজল্যুশন চেক করতে               | `nslookup example.com`             |
| `traceroute` | **Trace Route**                 | নেটওয়ার্ক পথ ট্রেস করতে              | `traceroute google.com`            |
| `arp`        | **Address Resolution Protocol** | IP ↔ MAC ম্যাপিং দেখতে               | `arp -a`                           |
| `tcpdump`    | **TCP Dump**                    | লাইভ নেটওয়ার্ক ট্রাফিক ক্যাপচার করতে | `sudo tcpdump -i eth0 port 80`     |

---

## 📂 File Integrity & Forensics

| Command     | Full Meaning         | কেন ব্যবহার হয়                            | বাস্তব Example        |
| ----------- | -------------------- | ----------------------------------------- | --------------------- |
| `md5sum`    | **MD5 Checksum**     | ফাইলের ইন্টেগ্রিটি যাচাই করতে             | `md5sum file.txt`     |
| `sha256sum` | **SHA-256 Checksum** | সিকিউর চেক করতে                           | `sha256sum file.txt`  |
| `file`      | **File Type**        | ফাইলের ধরন চেক করতে                       | `file exploit.bin`    |
| `strings`   | **Extract Strings**  | binary ফাইল থেকে readable টেক্সট বের করতে | `strings exploit.bin` |
| `hexdump`   | **Hex Dump**         | ফাইলের হেক্সাডেসিমাল ভিউ দেখতে            | `hexdump -C file.txt` |

---

## 📦 File Transfer & Remote Access

| Command | Full Meaning               | কেন ব্যবহার হয়               | বাস্তব Example                                      |
| ------- | -------------------------- | ---------------------------- | --------------------------------------------------- |
| `scp`   | **Secure Copy**            | রিমোট সার্ভারে ফাইল কপি করতে | `scp secret.txt user@192.168.1.5:/tmp/`             |
| `rsync` | **Remote Sync**            | দ্রুত ফাইল sync করতে         | `rsync -avz /home/user/ hacker@192.168.1.5:/backup` |
| `ftp`   | **File Transfer Protocol** | FTP সার্ভারে কানেক্ট করতে    | `ftp ftp.example.com`                               |
| `ssh`   | **Secure Shell**           | রিমোট লগইন করতে              | `ssh user@192.168.1.10`                             |

---

## 🖥️ Bash Scripting Essentials

| Command | Full Meaning              | কেন ব্যবহার হয়                    | বাস্তব Example                              |
| ------- | ------------------------- | --------------------------------- | ------------------------------------------- |
| `echo`  | **Echo Print**            | টেক্সট বা ভ্যারিয়েবল প্রিন্ট করতে | `echo "Hello Hacker"`                       |
| `read`  | **Read Input**            | ইউজার ইনপুট নিতে                  | `read name; echo $name`                     |
| `for`   | **For Loop**              | রিপিটেড টাস্ক অটোমেট করতে         | `for i in {1..5}; do echo $i; done`         |
| `while` | **While Loop**            | কন্ডিশনাল রিপিটেড কাজ             | `while true; do date; sleep 2; done`        |
| `if`    | **Conditional Execution** | শর্ত অনুসারে কাজ চালাতে           | `if [ -f file.txt ]; then echo "Found"; fi` |
| `grep`  | **Search with Regex**     | লগ বা ফাইল সার্চ করতে             | `grep "error" /var/log/syslog`              |
| `awk`   | **Pattern Processing**    | টেক্সট ফিল্ড প্রসেস করতে          | `awk '{print $1}' /etc/passwd`              |
| `sed`   | **Stream Editor**         | টেক্সট রিপ্লেস করতে               | `sed 's/root/admin/g' file.txt`             |
| `cut`   | **Cut Fields**            | টেক্সট থেকে নির্দিষ্ট কলাম কাটতে  | `cut -d: -f1 /etc/passwd`                   |
