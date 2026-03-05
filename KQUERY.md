# k-Anonymity query interface to wpa-sec

This interface allows for online and offline queries of the wpa-sec DB for leaked authentication credentials of WPA-protected WiFi networks. The API employs a k-Anonymity query scheme, which protects clients by not disclosing information on searched networks and wpa-sec users by not returning data that can be used to compromise the security of submitted networks.

More information on the k-Anonymity scheme [here](https://en.wikipedia.org/wiki/K-anonymity), [here](https://blog.cloudflare.com/validating-leaked-passwords-with-k-anonymity/), and [here](https://www.troyhunt.com/understanding-have-i-been-pwneds-use-of-sha-1-and-k-anonymity/).

## API

wpa-sec provides two query perspectives - by BSSID + SSID and by PMK. For every check, you'll need to craft a separate hash, use the first 4 hex chars from it as a cluster identifier (clid) and check if this hash ends with some of the values returned for this cluster. If the values match, the network is leaked.

### BSSID + SSID
API endpoint: `https://wpa-sec.stanev.org/bmacssid`

Used to query wpa-sec for leaked key by BSSID and SSID combination. This is useful when checking OTA WiFi AP scans for leaked credentials or already collected information and hashlines.

Here is the pseudocode:
```
bssid = 1c7ee5e2f2d0 # BSSID with leading zero. Only lowercase hex
ssid = 646c696e6b # 'dlink' in ascii. Only lowercase hex

hash = SHA1(bssid + ssid) # 1fe143ebc72790738a4346dc2a4e26ea92ed78a5

clid = LEFT(hash, 4) # '1fe1'

result = QUERY_WPASEC([clid])

foreach result[clid] as r
	if hash.endswith(r)
		LEAKED
```

Bash example:
```
BSSID=1c7ee5e2f2d0
SSID=$(echo -n dlink | xxd -p)

echo -n $BSSID$SSID | sha1sum
1fe143ebc72790738a4346dc2a4e26ea92ed78a5  -

curl -d '["1fe1"]' https://wpa-sec.stanev.org/bmacssid
{"1fe1":["cbc8ff3d","b9115798","0cfeca7c","78852df0","bdf01dd8","ef8c5a7f","92ed78a5","ff4fad63","e9dd48eb","1d0237a5","e4a0446d","49316650","c1337ee3","e15d97af","19a21302","17b3b7ac","f7594466","30c41eb2","4f38c8be","49551dd1","7c696243","ef824eaa","f513ef3c","7b45f218","f6965ae1","66e4ae94","189f50df","35cce6b5"]}
```
Here we compute cluster identifier `1fe1` and find our network with BSSID `1c7ee5e2f2d0` and SSID `dlink` has leaked credentials because the computed SHA1 hash end `92ed78a5` is present in returned suffixes for this cluster id.

wpa-sec accepts queries with more than one cluster identifier.

### PMK
API endpoint: `https://wpa-sec.stanev.org/bpmk`

Used to query wpa-sec for leaked key by [PMK](https://en.wikipedia.org/wiki/Pairwise_Master_Key). Essentially, this allows checking by a combination of SSID and password (PSK in WPA/WPA2), because PMK is computed by applying the [PBKDF2-HMAC-SHA1-4096](https://en.wikipedia.org/wiki/PBKDF2) function with PMK as password and SSID as salt. This is useful when we know the SSID of the network and the password - for example, extracted from the OS or stored in a secure manner by EDR.

Here is the pseudocode:
```
ssid = 646c696e6b # 'dlink' in ascii. Only lowercase hex
pass = 6161616131323334 # 'aaaa1234' in ascii. Only lowercase hex

pmk = PBKDF2(HMAC-SHA1, pass, ssid, 4096, 256) # 9fa59b70914dba97aa8eec2c62ea6e5d29ca4f20cf38f133d58d59309c601141
hash = SHA1(pmk) # de15471da9abe2f70ef54b337445f92b5cc685fd

clid = LEFT(hash, 4) # 'de15'

result = QUERY_WPASEC([clid])

foreach result[clid] as r
	if hash.endswith(r)
		LEAKED
```

Bash and OpenSSL example:
```
SSID=$(echo -n dlink | xxd -p)
PASS=$(echo -n aaaa1234 | xxd -p)

PMK=$(openssl kdf -binary -keylen 32 -kdfopt digest:sha1 -kdfopt hexpass:"$PASS" -kdfopt hexsalt:"$SSID" -kdfopt iter:4096 PBKDF2 | xxd -p -c 256)
echo -n $PMK | sha1sum
de15471da9abe2f70ef54b337445f92b5cc685fd  -

curl -d '["de15"]' https://wpa-sec.stanev.org/bpmk
{"de15":["75f8351a","5cc685fd","f2380924","fb2e497d","7d09ff1d","edb5acc6","8ccc2b0b","7d088401","f1d7f59d","b6cd0049","89603fcd","c4715d76","24edf826","a4857fcd","e1339301","4fb2fd72","7d69b4fd","a1bef7ad","f6869532","6d5c3bfd"]}
```
Here we compute cluster identifier `de15` and find our network with SSID `dlink` and PASS `aaaa1234` has leaked credentials because the computed SHA1 hash end `5cc685fd` is present in returned suffixes for this cluster identifier.

wpa-sec accepts queries with more than one cluster identifier.

## Offline check
wpa-sec k-anonymity DBs can be freely downloaded and queried offline. This is useful in case of security or regulatory constraints or if you need to check many networks.

The DBs are gzipped in JSON format:

[https://wpa-sec.stanev.org/data/wpasec_macssid.json.gz]()

[https://wpa-sec.stanev.org/data/wpasec_pmk.json.gz]()

Updated at least once a day.

## Notes on different query methods
The two query perspectives have different advantages and disadvantages. They serve different purposes, and returned results have to be interpreted depending on the use case.

### BSSID + SSID perspective
#### Pros
- Easily available input data from OS or over-the-air scanning
- Accessing SSID and BSSID usually doesn't require elevated system privileges
- Hashcat/John hashes contain needed data
- Suitable for OSINT research and data enrichment

#### Cons
- Possible false negatives: some classes of WiFi attacks (mostly AP-less) generate false BSSID, which will prevent identification of leaked network
- Possible false positives: we can't detect if the key was changed after a successful crack

### PMK perspective
#### Pros
- No false positives or negatives - successful hit guarantees the network credentials are leaked

#### Cons
- Requires access to network credentials, which require superuser OS-level access or may not be extractable at all
- Requires more computing for PMK calculation, if not already available

## Example implementation
Python implementation, which allows for manual query and checking saved WiFi network profiles + WiFi scan via NetworkManager under Linux, is available [here](misc/wpasec_q.py).

## FAQ
### Can I pull passwords from the k-Anonymity query interface?
No, you can't. The only information available is whether network credentials are leaked through wpa-sec or not.

### Is there a rate limit on the API?
Currently, no. We may introduce such if the traffic we get is too high. If you need to query many networks, use the offline DB dumps.