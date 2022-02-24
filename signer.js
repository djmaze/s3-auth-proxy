// This file contains code from the AWS SDK for JavaScript, licensed under Apache License 2.0.
// See https://github.com/aws/aws-sdk-js for more information.

const AWS = require("aws-sdk"),
    hmac = AWS.util.crypto.hmac,
    sha256 = AWS.util.crypto.sha256

let cachedKeys = {}
let cacheQueue = []
const maxCacheEntries = 50

class Signer {
    constructor(request, logger) {
        this.request = request
        this.headers = request.headers
        const [path, queryString] = request.url.split("?", 2)
        this.path = path
        this.query = AWS.util.queryStringParse(queryString)

        const regex =
            /(.+) Credential=(.+),\s*SignedHeaders=(.+),\s*Signature=(.+)/
        let match = regex.exec(this.headers.authorization)
        if (match) {
            this.presigned = false
            this.algorithm = match[1]
            this.credentialParts = match[2].split("/")
            this.signedHeaders = match[3]
            this.signedHeaderParts = this.signedHeaders.split(";")
            this.datetime = this.headers["x-amz-date"]

            this.region = this.credentialParts[2]
            this.service = this.credentialParts[3]
            this.requestIdentifier = this.credentialParts[4]

            if (this.algorithm != "AWS4-HMAC-SHA256") {
                logger.debug("headers:", this.headers)
                throw new Error(
                    `Unsupported signing algorithm ${this.algorithm}`
                )
            }

            this.authorizationHeader = this.headers.authorization
        } else {
            if (this.query.length) {
                logger.debug("query:", this.query)
                this.presigned = true
                this.algorithm = this.query["X-Amz-Algorithm"]
                this.credentials = this.query["X-Amz-Credential"]
                this.credentialParts = this.credentials.split("/")
                this.signedHeaders = this.query["X-Amz-SignedHeaders"]
                this.signedHeaderParts = this.signedHeaders.split(";")
                this.datetime = this.query["X-Amz-Date"]

                this.region = this.credentialParts[2]
                this.service = this.credentialParts[3]
                this.requestIdentifier = this.credentialParts[4]

                const signature = this.query["X-Amz-Signature"]

                if (this.algorithm != "AWS4-HMAC-SHA256") {
                    throw `Unsupported signing algorithm ${this.algorithm}`
                }

                this.authorizationHeader = `${this.algorithm} Credential=${this.credentials}, SignedHeaders=${this.signedHeaders}, Signature=${signature}`
            } else {
                logger.debug("headers:", this.headers)
                throw new Error("Credentials missing")
            }
        }
    }

    changeAuthorization(newHost, accessKeyId, secretAccessKey) {
        this.headers.host = newHost

        if (this.presigned) {
            this.query["X-Amz-Credential"] = this.credentialString(accessKeyId)
            this.query["X-Amz-Signature"] = this.signature(
                accessKeyId,
                secretAccessKey,
                this.datetime
            )
        } else {
            this.headers.authorization = this.authorizationHeaderFor(
                accessKeyId,
                secretAccessKey
            )
        }
    }

    authorizationHeaderFor(accessKeyId, secretAccessKey) {
        var parts = []
        parts.push(
            this.algorithm + " Credential=" + this.credentialString(accessKeyId)
        )
        parts.push("SignedHeaders=" + this.signedHeaders)
        parts.push(
            "Signature=" +
                this.signature(accessKeyId, secretAccessKey, this.datetime)
        )
        return parts.join(", ")
    }

    credentialString(accessKeyId) {
        this.credentialParts[0] = accessKeyId
        return this.credentialParts.join("/")
    }

    signature(accessKeyId, secretAccessKey, datetime) {
        const signingKey = this.getSigningKey(
            accessKeyId,
            secretAccessKey,
            datetime.substr(0, 8)
        )
        return hmac(signingKey, this.stringToSign(datetime), "hex")
    }

    getSigningKey(accessKeyId, secretAccessKey, date) {
        const credsIdentifier = hmac(secretAccessKey, accessKeyId, "base64")
        const cacheKey = [
            credsIdentifier,
            date,
            this.region,
            this.service,
        ].join("_")
        if (cacheKey in cachedKeys) {
            return cachedKeys[cacheKey]
        } else {
            const kDate = hmac("AWS4" + secretAccessKey, date, "buffer")
            const kRegion = hmac(kDate, this.region, "buffer")
            const kService = hmac(kRegion, this.service, "buffer")
            const signingKey = hmac(kService, this.requestIdentifier, "buffer")

            cachedKeys[cacheKey] = signingKey
            cacheQueue.push(cacheKey)
            if (cacheQueue.length > maxCacheEntries) {
                // remove the oldest entry (not the least recently used)
                delete cachedKeys[cacheQueue.shift()]
            }

            return signingKey
        }
    }

    stringToSign(datetime) {
        var parts = []
        parts.push("AWS4-HMAC-SHA256")
        parts.push(datetime)
        parts.push(this.scope())
        parts.push(this.hexEncodedHash(this.canonicalString()))
        return parts.join("\n")
    }

    scope() {
        return this.credentialParts.slice(1).join("/")
    }

    canonicalString() {
        var parts = []

        parts.push(this.request.method)
        parts.push(this.path)
        parts.push(this.queryStringWithoutSignature())
        parts.push(this.canonicalHeaders() + "\n")
        parts.push(this.signedHeaders)
        if (this.presigned) {
            parts.push("UNSIGNED-PAYLOAD")
        } else {
            parts.push(this.hexEncodedBodyHash())
        }

        return parts.join("\n")
    }

    canonicalHeaders() {
        let parts = []
        this.signedHeaderParts.forEach((key) => {
            parts.push(key + ":" + this.headers[key])
        })
        return parts.join("\n")
    }

    hexEncodedBodyHash() {
        if (this.headers["x-amz-content-sha256"]) {
            return this.headers["x-amz-content-sha256"]
        } else {
            return this.hexEncodedHash(this.request.body || "")
        }
    }

    hexEncodedHash(string) {
        return sha256(string, "hex")
    }

    pathWithQuery() {
        if (this.query) {
            return [this.path, AWS.util.queryParamsToString(this.query)].join(
                "?"
            )
        } else {
            return this.path
        }
    }

    queryStringWithoutSignature() {
        const q = { ...this.query }
        delete q["X-Amz-Signature"]
        return AWS.util.queryParamsToString(q)
    }
}

module.exports = Signer
