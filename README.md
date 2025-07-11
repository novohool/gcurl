# gcurl
!! 研究目的,不对能用于其他目的，概不负责
如果需要获取未污染ip和域名使用以下工具

# 安装工具
` pip install dns-observe`
# 运行工具，观察 dns 结果，找到能用的IP
- dns-observe v2ex.com
>  Time: 2024-11-25 18:34:13.965648, Name: v2ex.com, TTL: 77, A: 157.240.17.41  
>  Time: 2024-11-25 18:34:13.969059, Name: v2ex.com, TTL: 250, A: 108.160.167.148  
>  Time: 2024-11-25 18:34:14.097316, Name: v2ex.com, TTL: 300, A: 104.20.47.180  
>  Time: 2024-11-25 18:34:14.097316, Name: v2ex.com, TTL: 300, A: 104.20.48.180  
>  Time: 2024-11-25 18:34:14.097316, Name: v2ex.com, TTL: 300, A: 172.67.35.211  

# 和curl使用对比
- curl访问直接被重置
```
D:\workspace\gcurl>curl -k -I -v  --resolve v2ex.com:443:172.67.35.211  https://v2ex.com  
* Added v2ex.com:443:172.67.35.211 to DNS cache
* Hostname v2ex.com was found in DNS cache
*   Trying 172.67.35.211:443...
* Connected to v2ex.com (172.67.35.211) port 443
* schannel: disabled automatic use of client certificate
* ALPN: curl offers http/1.1
* Recv failure: Connection was reset
* schannel: failed to receive handshake, SSL/TLS connection failed
* closing connection #0
curl: (35) Recv failure: Connection was reset
```
- gcurl访问可绕过封禁
```
D:\workspace\gcurl>gcurl -k -I -v  --resolve v2ex.com:443:172.67.35.211  https://v2ex.com   
[DEBUG] param: h3,h2, type: *dns.SVCBAlpn
[DEBUG] param: 172.66.133.207,172.67.35.211, type: *dns.SVCBIPv4Hint
[DEBUG] param: AEX+DQBBTwAgACCp+YGMzxGKA3+kY2En/UwOpQvBQMorwhNR3jonlOx/OwAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=, type: *dns.SVCBECHConfig
[DEBUG] Trying base64 decode of param.String(): AEX+DQBBTwAgACCp+YGMzxGKA3+kY2En/UwOpQvBQMorwhNR3jonlOx/OwAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=
[DEBUG] base64 decode success, len=71
[VERBOSE] ECHConfigList contains 1 configs:
[VERBOSE]   Config[0]: {Version:65037 Length:65 Contents:{KeyConfig:{ConfigId:79 KemId:32 PublicKey:a9f9818ccf118a037fa4636127fd4c0ea50bc140ca2bc21351de3a2794ec7f3b rawPublicKey:[169 249 129 140 207 17 138 3 127 164 99 97 39 253 76 14 165 11 193 64 202 43 194 19 81 222 58 39 148 236 127 59] CipherSuites:[{KdfId:1 AeadId:1}]} MaximumNameLength:0 PublicName:[99 108 111 117 100 102 108 97 114 101 45 101 99 104 46 99 111 109] rawExtensions:[]} raw:[254 13 0 65 79 0 32 0 32 169 249 129 140 207 17 138 3 127 164 99 97 39 253 76 14 165 11 193 64 202 43 194 19 81 222 58 39 148 236 127 59 0 4 0 1 0 1 0 18 99 108 111 117 100 102 108 97 114 101 45 101 99 104 46 99 111 109 0 0]}
2025/07/10 17:34:42 [VERBOSE] Using ECH for original host v2ex.com, not spoofing ClientHello
2025/07/10 17:34:42 [VERBOSE] Starting request: URL=https://v2ex.com, HeadOnly=true, Insecure=true, GenerateCert=true, FollowRedirects=false, EnableSNIRewrite=false
2025/07/10 17:34:42 [VERBOSE] Host Rules: map[]
2025/07/10 17:34:42 [VERBOSE] Host Resolver Rules: map[]
2025/07/10 17:34:42 [VERBOSE] Resolve Rules: map[v2ex.com:443:172.67.35.211]
2025/07/10 17:34:42 [VERBOSE] DialTLSContext: network=tcp, addr=v2ex.com:443, host=v2ex.com
[DEBUG] param: h3,h2, type: *dns.SVCBAlpn
[DEBUG] param: 172.66.133.207,172.67.35.211, type: *dns.SVCBIPv4Hint
[DEBUG] param: AEX+DQBB2gAgACD0CR4vFceTFWhzEeOAADeEuNFBGlQkfzbx22KpqnTWSQAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=, type: *dns.SVCBECHConfig
[DEBUG] Trying base64 decode of param.String(): AEX+DQBB2gAgACD0CR4vFceTFWhzEeOAADeEuNFBGlQkfzbx22KpqnTWSQAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=
[DEBUG] base64 decode success, len=71
[VERBOSE] ECHConfigList contains 1 configs:
[VERBOSE]   Config[0]: {Version:65037 Length:65 Contents:{KeyConfig:{ConfigId:218 KemId:32 PublicKey:f4091e2f15c79315687311e380003784b8d1411a54247f36f1db62a9aa74d649 rawPublicKey:[244 9 30 47 21 199 147 21 104 115 17 227 128 0 55 132 184 209 65 26 84 36 127 
54 241 219 98 169 170 116 214 73] CipherSuites:[{KdfId:1 AeadId:1}]} MaximumNameLength:0 PublicName:[99 108 111 117 100 102 108 97 114 101 45 101 99 104 46 99 111 109] rawExtensions:[]} raw:[254 13 0 65 218 0 32 0 32 244 9 30 47 21 199 147 21 104 115 17 227 
128 0 55 132 184 209 65 26 84 36 127 54 241 219 98 169 170 116 214 73 0 4 0 1 0 1 0 18 99 108 111 117 100 102 108 97 114 101 45 101 99 104 46 99 111 109 0 0]}
2025/07/10 17:34:42 [VERBOSE] Using ECH for original host v2ex.com, not spoofing ClientHello
2025/07/10 17:34:42 [VERBOSE] Using ServerName="v2ex.com" (fallback=false)
2025/07/10 17:34:42 [VERBOSE] Applying resolve rule: v2ex.com:443 -> 172.67.35.211
2025/07/10 17:34:42 [VERBOSE] Dialing TCP: network=tcp, addr=172.67.35.211:443
2025/07/10 17:34:43 [VERBOSE] TCP connection established: local=10.66.2.46:50910, remote=172.67.35.211:443
2025/07/10 17:34:43 [VERBOSE] TLS Client Hello Details (Fingerprint: golang (default)):
2025/07/10 17:34:43 [VERBOSE]   Cipher Suites: [Not available before handshake]
2025/07/10 17:34:43 [VERBOSE]   Extensions: [Not available before handshake]
2025/07/10 17:34:43 [VERBOSE]   Supported Curves: [Not available before handshake]
2025/07/10 17:34:43 [VERBOSE]   Supported Points: [Not available before handshake]
2025/07/10 17:34:43 [VERBOSE]   Supported Versions: [TLS1.3]
2025/07/10 17:34:43 [VERBOSE]   ServerName=v2ex.com
2025/07/10 17:34:44 [VERBOSE] TLS Handshake completed: Version=TLS1.3, CipherSuite=TLS_AES_128_GCM_SHA256, ServerName=v2ex.com
2025/07/10 17:34:44 [VERBOSE] Server Certificate: Subject=CN=v2ex.com, Issuer=CN=E6,O=Let's Encrypt,C=US, SANs=[*.v2ex.com v2ex.com]
HTTP/1.1 200 200 OK
Google: XY
X-Frame-Options: sameorigin
Report-To: {"endpoints":[{"url":"https:\/\/a.nel.cloudflare.com\/report\/v4?s=ljfNdEev99NWEEzLlXh9qOsFeBLh7vCSNGGPLNTVpHHaDLALL278Qgp8eaWxsTbYgshHQbQ0t9CYz%2FLpeMDQ6ucIOVU4DxEiz%2BLI2qf%2BOhRSW9MusTP9V2ax"}],"group":"cf-nel","max_age":604800}
Alt-Svc: h3=":443"; ma=86400
Content-Type: text/html; charset=UTF-8
Cf-Ray: 95cf112c4a891182-FRA
Cf-Cache-Status: DYNAMIC
Nel: {"success_fraction":0,"report_to":"cf-nel","max_age":604800}
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Server: cloudflare
Date: Thu, 10 Jul 2025 09:34:45 GMT
Set-Cookie: PB3_SESSION="2|1:0|10:1752140085|11:PB3_SESSION|36:djJleDo1OC4zNC4yMDguMjU0Ojg1MTIwMjk1|887e26583569c451f4aef87b06e17b3a3d2d12d506c05d379e9aa6384c8ece46"; expires=Tue, 15 Jul 2025 09:34:45 GMT; httponly; Path=/, V2EX_LANG=zhcn; Path=/
Server-Timing: cfL4;desc="?proto=TCP&rtt=229742&min_rtt=229742&rtt_var=114871&sent=7&recv=7&lost=0&retrans=2&sent_bytes=3896&recv_bytes=1773&delivery_rate=1584&cwnd=33&unsent_bytes=0&cid=6c62a3e5b836c62c&ts=1628&x=0"

```
