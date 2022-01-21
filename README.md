# s3-auth-proxy

[![Build Status](https://ci.strahlungsfrei.de/api/badges/djmaze/s3-auth-proxy/status.svg)](https://ci.strahlungsfrei.de/djmaze/s3-auth-proxy)
[![Docker Stars](https://img.shields.io/docker/stars/mazzolino/s3-auth-proxy.svg)](https://hub.docker.com/r/mazzolino/s3-auth-proxy/) [![Docker Pulls](https://img.shields.io/docker/pulls/mazzolino/s3-auth-proxy.svg)](https://hub.docker.com/r/mazzolino/s3-auth-proxy/)

Reverse proxy for S3-compatible services which allows to restrict access to selected buckets.

This is especially useful for DigitalOcean, because they currently do not provide a way to set permissions for their _Spaces_ product.

**Note:** Your client needs to be configured to use _path-based access_ as opposed to the subdomain-based one.

Listens on port 8000.

## Usage

The app needs the following env variables to be set:

-   `ACCESSKEYID`: S3 access key id for proxy
-   `SECRETACCESSKEY`: S3 secret access key for proxy
-   `UPSTREAM_URL`: URL of upstream S3 service (e.g. `https://fra1.digitaloceanspaces.com`)
-   `UPSTREAM_ACCESSKEY`: S3 access key id for upstream service
-   `UPSTREAM_SECRETACCESSKEY`: S3 secret access key for upstream service
-   `ALLOWED_BUCKETS`: whitelist of buckets to proxy (comma-separated)

### With Docker Compose

Copy _.env.sample_ to _.env_ and adjust the values as described above.

Then run `docker-compose up -d`.

### With Docker

Example:

```bash
docker run -d \
  -p 8000:8000
  -e ACCESSKEYID=proxyaccess12345678 \
  -e SECRETACCESSKEY=proxysecret987654210 \
  -e UPSTREAM_URL=https://fra1.digitaloceanspaces.com \
  -e UPSTREAM_ACCESSKEYID=doaccess12345678 \
  -e UPSTREAM_SECRETACCESSKEY=dosecret9876543210 \
  -e ALLOWED_BUCKETS=my-foobar-testbucket,another-testbucket \
  mazzolino/s3-auth-proxy
```

The buckets are now available at http://localhost:8000. Non-specified buckets are not available.

### Without Docker

-   Install NodeJS 12
-   `npm install`
-   `env ACCESSKEYID=... SECRETACCESSKEY=... UPSTREAM_URL=... UPSTREAM_ACCESSKEYID=... UPSTREAM_SECRETACCESSKEY=... ALLLOWED_BUCKETS=... npm start`

## TODO

-   [ ] Only show whitelisted buckets in list
-   [ ] Allow wildcards for bucket whitelisting
-   [ ] Allow restricting to read-only access

## Credits

This project has been shamelessly adapted from [s3-reverse-proxy](https://github.com/armaniacs/s3-reverse-proxy) (licensed under Apache 2.0). Thanks!
