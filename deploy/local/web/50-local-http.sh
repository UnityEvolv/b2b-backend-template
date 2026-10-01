#!/bin/sh
# Local only: the web apps are served over plain http on localhost, where
# the frontend's upgrade-insecure-requests would send the pages' API calls to
# an https gateway that does not exist, and Strict-Transport-Security means
# nothing. Both are dropped from the headers the frontend's own start script
# (40-app-headers.sh) wrote; everything else is served as deployed.
set -eu
conf=/etc/nginx/app/headers.conf
sed -i -e 's/; upgrade-insecure-requests//' -e '/Strict-Transport-Security/d' "$conf"
