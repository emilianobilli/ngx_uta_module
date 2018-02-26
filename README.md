# ngx_uta_module
Url Token Authorization for Nginx

To install, compile nginx with this ./configure option:

./configure --add-module=/path/to/uta/module


If is defined to use URL Token Authentication, the cache engine processes the query string and creates up to four additional request headers. Those headers contain the authentication token, or hash, the not-valid-before and/or not-valid-after times, and the balance of the URL, less the authentication token and tokens to be ignored in the comparison.
The secret number is then validated against the Secrets Table and its usability determined based upon the specified not-valid-before and not-valid-after times. The Content Distributor then invokes the hash algorithm using the indicated shared secret and compares the result to the authentication token.
If matched, the request is considered valid unless time restrictions are defined and embedded in the URL. If not matched, the request is rejected with the specified status code.
If time-based validity checking is indicated, the time that the request was received at the Content Distributor is compared to “not-valid-before” or “not-valid-after” specifications and the request validated or rejected accordingly.
If the request is rejected, the defined error action is taken and an Extended Status Code is included in the log record indicating the results of the authentication checks.


location / {
            root /home/ubuntu;
            uta;			/* Enable module */
            secret secret_to_hash;	/* Secret */
            hmac sha1;			/* sha1 or sha256 */
        }

E.

