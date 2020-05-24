// This file contains code from the AWS SDK for JavaScript, licensed under Apache License 2.0.
// See https://github.com/aws/aws-sdk-js for more information.

const AWS = require("aws-sdk"),
      hmac = AWS.util.crypto.hmac,
      sha256 = AWS.util.crypto.sha256;

let cachedKeys = {}
let cacheQueue = []
const maxCacheEntries = 50

class Signer {
  constructor(request, headers) {
    this.request = request
    const regex = /(.+) Credential=(.+),\s*SignedHeaders=(.+),\s*Signature=(.+)/
    let match = regex.exec(headers.authorization)
    this.headers = headers
    this.algorithm = match[1]
    this.credentialParts = match[2].split('/')
    this.signedHeaders = match[3]
    this.signedHeaderParts = this.signedHeaders.split(';')

    this.region = this.credentialParts[2]
    this.service = this.credentialParts[3]
    this.requestIdentifier = this.credentialParts[4]

    if (this.algorithm != 'AWS4-HMAC-SHA256') {
      throw(`Unsupported signing algorithm ${this.algorithm}`)
    }
  }

  changeAuthorization(accessKeyId, secretAccessKey) {
    this.headers.authorization = this.authorization(
      accessKeyId, 
      secretAccessKey,
      this.headers['x-amz-date']
    )
  }

  authorization(accessKeyId, secretAccessKey, datetime) {
    var parts = [];
    parts.push(this.algorithm + " " + this.credentialString(accessKeyId));
    parts.push('SignedHeaders=' + this.signedHeaders);
    parts.push('Signature=' + this.signature(accessKeyId, secretAccessKey, datetime));
    return parts.join(', ');
  }

  credentialString(accessKeyId) {
    this.credentialParts[0] = accessKeyId
    return "Credential=" + this.credentialParts.join('/')
  }

  signature(accessKeyId, secretAccessKey, datetime) {
    const signingKey = this.getSigningKey(accessKeyId, secretAccessKey, datetime.substr(0, 8))
    return hmac(signingKey, this.stringToSign(datetime), 'hex');
  }

  getSigningKey(accessKeyId, secretAccessKey, date) {
    const credsIdentifier = hmac(secretAccessKey, accessKeyId, 'base64');
    const cacheKey = [credsIdentifier, date, this.region, this.service].join('_');
    if (cacheKey in cachedKeys) {
      return cachedKeys[cacheKey]
    } else {
      const kDate = hmac(
        'AWS4' + secretAccessKey,
        date,
        'buffer'
      );
      const kRegion = hmac(kDate, this.region, 'buffer');
      const kService = hmac(kRegion, this.service, 'buffer');
      const signingKey = hmac(kService, this.requestIdentifier, 'buffer');

      cachedKeys[cacheKey] = signingKey;
      cacheQueue.push(cacheKey);
      if (cacheQueue.length > maxCacheEntries) {
        // remove the oldest entry (not the least recently used)
        delete cachedSecret[cacheQueue.shift()];
      }

      return signingKey
    }
  }

  stringToSign(datetime) {
    var parts = [];
    parts.push('AWS4-HMAC-SHA256');
    parts.push(datetime);
    parts.push(this.scope(datetime));
    parts.push(this.hexEncodedHash(this.canonicalString()));
    return parts.join('\n');
  }

  scope(datetime) {
    return this.credentialParts.slice(1).join('/')
  }

  canonicalString() {
    var parts = [], pathname = this.pathname();

    parts.push(this.request.method);
    parts.push(pathname);
    parts.push(this.request_search());
    parts.push(this.canonicalHeaders() + '\n');
    parts.push(this.signedHeaders);
    parts.push(this.hexEncodedBodyHash());

    return parts.join('\n');
  }

  canonicalHeaders() {
    let parts = [];
    this.signedHeaderParts.forEach((key) => {
      parts.push(key + ':' + this.headers[key])
    })
    return parts.join('\n')
  }

  hexEncodedBodyHash() {
    if (this.headers['x-amz-content-sha256']) {
      return this.headers['x-amz-content-sha256'];
    } else {
      return this.hexEncodedHash(this.request.body || '');
    }
  }

  hexEncodedHash(string) {
    return sha256(string, 'hex');
  }

  pathname() {
    return this.request.url.split('?', 1)[0];
  }

  request_search() {
    let query = this.request.url.split('?', 2)[1];
    if (query) {
      query = AWS.util.queryStringParse(query);
      return AWS.util.queryParamsToString(query);
    }
    return '';
  }
}

module.exports = Signer;
