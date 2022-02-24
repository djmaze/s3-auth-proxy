// This file contains code from s3-reverse-proxy, licensed under Apache License 2.0.
// See https://github.com/armaniacs/s3-reverse-proxy for more information.

const http = require("http"),
    https = require("https"),
    Signer = require("./signer"),
    winston = require("winston")

const port = 8000,
    accessKeyId = process.env.ACCESSKEYID,
    secretAccessKey = process.env.SECRETACCESSKEY,
    upstreamURL = new URL(process.env.UPSTREAM_URL),
    upstreamAccessKeyId = process.env.UPSTREAM_ACCESSKEYID,
    upstreamSecretAccessKey = process.env.UPSTREAM_SECRETACCESSKEY,
    allowedBuckets = process.env.ALLOWED_BUCKETS.split(","),
    logLevel = process.env.LOG_LEVEL || "info"

const logger = winston.createLogger({
    level: logLevel,
    format: winston.format.combine(
        winston.format.errors({ stack: true }),
        winston.format.colorize(),
        winston.format.simple()
    ),
    transports: [new winston.transports.Console()],
})

var main = function () {
    http.createServer(handle_request).listen(port, "0.0.0.0")
    logger.info(
        "101\tSTART\t-\t-\tProxying to " + upstreamURL.href + " on port " + port
    )
    logger.info("101\tSTART\t-\t-\tAllowed buckets:", allowedBuckets)
}

var handle_request = function (client_request, client_response) {
    try {
        const verificationSigner = new Signer(client_request, logger)
        const givenClientAuthorization = verificationSigner.authorizationHeader
        const correctClientAuthorization =
            verificationSigner.authorizationHeaderFor(
                accessKeyId,
                secretAccessKey
            )

        if (
            givenClientAuthorization.replace(/\s/g, "") !==
            correctClientAuthorization.replace(/\s/g, "")
        ) {
            logger.error("incorrect authorization", givenClientAuthorization)
            client_response.writeHead(403)
            client_response.end()
            return
        }

        const bucket = client_request.url.split(/[/?]/)[1]
        if (
            bucket &&
            !allowedBuckets.includes(bucket) &&
            !bucket.startsWith("probe-bucket-sign-")
        ) {
            logger.error("disallowed bucket", bucket)
            client_response.writeHead(403)
            client_response.end()
            return
        }

        const signer = new Signer(client_request, logger)
        signer.changeAuthorization(
            upstreamURL.host,
            upstreamAccessKeyId,
            upstreamSecretAccessKey
        )

        let options = {
            protocol: upstreamURL.protocol,
            host: upstreamURL.hostname,
            port: upstreamURL.port,
            method: client_request.method,
            path: signer.pathWithQuery(),
            headers: signer.headers,
        }

        let upstream_request
        if (options.protocol == "https:") {
            upstream_request = https.request(options)
        } else {
            upstream_request = http.request(options)
        }

        client_request.addListener("data", function (chunk) {
            upstream_request.write(chunk)
        })
        client_request.addListener("end", function () {
            upstream_request.end()
        })

        upstream_request.addListener("response", function (upstream_response) {
            client_response.writeHead(
                upstream_response.statusCode,
                upstream_response.headers
            )
            var size = 0
            upstream_response.addListener("data", function (chunk) {
                client_response.write(chunk)
                size += chunk.length
            })
            upstream_response.addListener("end", function () {
                logger.info(
                    upstream_response.statusCode +
                        "\t" +
                        client_request.method +
                        "\t" +
                        client_request.url +
                        "\t" +
                        size
                )
                client_response.end()
            })
        })
    } catch (err) {
        logger.error(`Error handling request: ${client_request.url}`)
        logger.error(err)
        client_response.writeHead(500)
        client_response.end()
        return
    }
}

main()
