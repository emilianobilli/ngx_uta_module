# ngx_uta_module
Url Token Authorization for Nginx

To install, compile nginx with this ./configure option:
```
# sudo apt-get install libssl-dev
./configure --add-module=/path/to/uta/module --with-http_ssl_module
```

If is defined to use URL Token Authentication, the cache engine processes the query string and creates up to four additional request headers. Those headers contain the authentication token, or hash, the not-valid-before and/or not-valid-after times, and the balance of the URL, less the authentication token and tokens to be ignored in the comparison.
The secret number is then validated against the Secrets Table and its usability determined based upon the specified not-valid-before and not-valid-after times. The Content Distributor then invokes the hash algorithm using the indicated shared secret and compares the result to the authentication token.
If matched, the request is considered valid unless time restrictions are defined and embedded in the URL. If not matched, the request is rejected with the specified status code.
If time-based validity checking is indicated, the time that the request was received at the Content Distributor is compared to “not-valid-before” or “not-valid-after” specifications and the request validated or rejected accordingly.
If the request is rejected, the defined error action is taken and an Extended Status Code is included in the log record indicating the results of the authentication checks.

## Configuration
```
location / {
            root /home/ubuntu;
            uta;			/* Enable module */
            secret secret_to_hash;	            /* Secret */
            time_expiration on;                 /* user params stime and etime */
            hmac sha1;			/* sha1 or sha256 */
        }
```
## Time Expiration
```
    time_expiration on|off;
    ?stime=AAAAMMDDHHMM&etime=AAAAMMDDHHMM
    
```
## URL Format
The URL generated for the resource being protected should have all parameters required for normal operation plus those required for the URL security needed. These normally consist of query string keywords defining the time parameters, a keyword specifying the hash value and any additional parameters generated by the origin server.

The hashed value to be appended to the URL indicates which secret from the table is to be used (0-9), followed by the first twenty characters of the resulting hash. Actually in this version only 1 secret is available.

Example:
```
1- Remove protocol, hostname and clientId from hash input leaving:
/path1/resource?&product=A123&otherstuff=xyz

2- Add desired arbitrary or time validity tokens:
e.g. /path1/resource?&product=A123&otherstuff=xyz&stime=20081201060100&etime=20081201183000

3- Translate result to lower-case if the origin server is case-insensitive (e.g. Windows).
Calculate the result to an HMAC-SHA1 hash using the result of step 1 or 2 and the secret: randomgarbledcharacters

4- Build new URL:
http:www.sample.com/path1/resource?clientId=12345&product=A123&otherstuff
=xyz&stime=20081201060100&etime=20081201183000&encoded=0first20chars-of-hash
```

E.

