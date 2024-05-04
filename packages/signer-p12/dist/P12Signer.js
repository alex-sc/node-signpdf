"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.P12Signer = void 0;
var _nodeForge = _interopRequireWildcard(require("node-forge"));
var _utils = require("@signpdf/utils");
var _jsrsasign = _interopRequireDefault(require("jsrsasign"));
var _axios = _interopRequireDefault(require("axios"));
function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }
function _getRequireWildcardCache(nodeInterop) { if (typeof WeakMap !== "function") return null; var cacheBabelInterop = new WeakMap(); var cacheNodeInterop = new WeakMap(); return (_getRequireWildcardCache = function (nodeInterop) { return nodeInterop ? cacheNodeInterop : cacheBabelInterop; })(nodeInterop); }
function _interopRequireWildcard(obj, nodeInterop) { if (!nodeInterop && obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(nodeInterop); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }
function timestampToAsn1(timeStampToken) {
  // Timestamp unsigned attribute
  const timestampValue = _nodeForge.default.asn1.create(_nodeForge.default.asn1.Class.UNIVERSAL, _nodeForge.default.asn1.Type.SET, true, [timeStampToken]);
  return _nodeForge.asn1.create(_nodeForge.asn1.Class.UNIVERSAL, _nodeForge.asn1.Type.SEQUENCE, true, [
  // AttributeType
  _nodeForge.asn1.create(_nodeForge.asn1.Class.UNIVERSAL, _nodeForge.asn1.Type.OID, false, _nodeForge.asn1.oidToDer('1.2.840.113549.1.9.16.2.14').getBytes()), timestampValue]);
}
const tsa = async ({
  tsaUrl,
  signature
}) => {
  // Generate SHA256 hash from signature content for TSA
  const md = _nodeForge.default.md.sha256.create();
  md.update(signature);
  const digest = md.digest().getBytes();
  const request = new _jsrsasign.default.asn1.tsp.TimeStampReq({
    messageImprint: {
      alg: 'sha256',
      hash: Buffer.from(digest, 'binary').toString('hex')
    },
    certreq: true
  });
  const requestHex = request.getEncodedHex();
  const tsr = _nodeForge.default.util.hexToBytes(requestHex);
  try {
    const response = await (0, _axios.default)({
      method: 'post',
      url: tsaUrl,
      data: Buffer.from(tsr, 'binary'),
      headers: {
        'Content-Type': 'application/timestamp-query'
      },
      responseType: 'arraybuffer',
      responseEncoding: 'binary'
    });
    const responseAsn1 = _nodeForge.default.asn1.fromDer(response.data.toString('binary'));

    // Return the token (it contains cert data)
    return responseAsn1.value[1];
  } catch (error) {
    return undefined;
  }
};

/**
 * @param {Asn1} newAttr
 * @param {Asn1} asn
 * @param {string[]} path
 * @param {number} level
 */
function dump(newAttr, asn, path = [], level = 0) {
  if (Array.isArray(asn.value)) {
    if (asn.value.length === 6 && JSON.stringify(path) === JSON.stringify([16, 0, 16, 17])) {
      // 0: version
      // 1: sid
      // 2: digestAlgorithm
      // 3: SignedAttributes
      // 4: signatureAlgorithm
      // 5: signature
      // eslint-disable-next-line no-param-reassign
      asn.value = [...asn.value, newAttr];
    }
    for (let i = 0; i < asn.value.length; i += 1) {
      const child = asn.value[i];
      const newPath = [...path];
      newPath.push(asn.type);
      dump(newAttr, child, newPath, level + 1);
    }
  }
}

/**
 * @typedef {object} SignerOptions
 * @prop {string} [passphrase]
 * @prop {boolean} [asn1StrictParsing]
 */

class P12Signer extends _utils.Signer {
  /**
   * @param {Buffer | Uint8Array | string} p12Buffer
   * @param {SignerOptions} additionalOptions
   */
  constructor(p12Buffer, additionalOptions = {}) {
    super();
    const buffer = (0, _utils.convertBuffer)(p12Buffer, 'p12 certificate');
    this.options = {
      asn1StrictParsing: false,
      passphrase: '',
      ...additionalOptions
    };
    this.cert = _nodeForge.default.util.createBuffer(buffer.toString('binary'));
  }

  /**
   * @param {Buffer} pdfBuffer
   * @param {Date | undefined} signingTime
   * @returns {Promise<Buffer>}
   */
  async sign(pdfBuffer, signingTime = undefined) {
    if (!(pdfBuffer instanceof Buffer)) {
      throw new _utils.SignPdfError('PDF expected as Buffer.', _utils.SignPdfError.TYPE_INPUT);
    }

    // Convert Buffer P12 to a forge implementation.
    const p12Asn1 = _nodeForge.default.asn1.fromDer(this.cert);
    const p12 = _nodeForge.default.pkcs12.pkcs12FromAsn1(p12Asn1, this.options.asn1StrictParsing, this.options.passphrase);

    // Extract safe bags by type.
    // We will need all the certificates and the private key.
    const certBags = p12.getBags({
      bagType: _nodeForge.default.pki.oids.certBag
    })[_nodeForge.default.pki.oids.certBag];
    const keyBags = p12.getBags({
      bagType: _nodeForge.default.pki.oids.pkcs8ShroudedKeyBag
    })[_nodeForge.default.pki.oids.pkcs8ShroudedKeyBag];
    const privateKey = keyBags[0].key;
    // Here comes the actual PKCS#7 signing.
    const p7 = _nodeForge.default.pkcs7.createSignedData();
    // Start off by setting the content.
    p7.content = _nodeForge.default.util.createBuffer(pdfBuffer.toString('binary'));

    // Then add all the certificates (-cacerts & -clcerts)
    // Keep track of the last found client certificate.
    // This will be the public key that will be bundled in the signature.
    let certificate;
    Object.keys(certBags).forEach(i => {
      const {
        publicKey
      } = certBags[i].cert;
      p7.addCertificate(certBags[i].cert);

      // Try to find the certificate that matches the private key.
      if (privateKey.n.compareTo(publicKey.n) === 0 && privateKey.e.compareTo(publicKey.e) === 0) {
        certificate = certBags[i].cert;
      }
    });
    if (typeof certificate === 'undefined') {
      throw new _utils.SignPdfError('Failed to find a certificate that matches the private key.', _utils.SignPdfError.TYPE_INPUT);
    }

    // Add a sha256 signer. That's what Adobe.PPKLite adbe.pkcs7.detached expects.
    // Note that the authenticatedAttributes order is relevant for correct
    // EU signature validation:
    // https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/validation
    p7.addSigner({
      key: privateKey,
      certificate,
      digestAlgorithm: _nodeForge.default.pki.oids.sha256,
      authenticatedAttributes: [{
        type: _nodeForge.default.pki.oids.contentType,
        value: _nodeForge.default.pki.oids.data
      }, {
        type: _nodeForge.default.pki.oids.signingTime,
        // value can also be auto-populated at signing time
        value: signingTime !== null && signingTime !== void 0 ? signingTime : new Date()
      }, {
        type: _nodeForge.default.pki.oids.messageDigest
        // value will be auto-populated at signing time
      }]
    });

    // Sign in detached mode.
    p7.sign({
      detached: true
    });
    if (this.options.tsaUrl) {
      const forgeSignature = p7.signers[0].signature;
      const timeStampToken = await tsa({
        tsaUrl: this.options.tsaUrl,
        signature: forgeSignature
      });
      const asn = p7.toAsn1();
      if (timeStampToken) {
        const attrsAsn1 = _nodeForge.asn1.create(_nodeForge.asn1.Class.CONTEXT_SPECIFIC, 1, true, []);
        attrsAsn1.value.push(timestampToAsn1(timeStampToken));
        dump(attrsAsn1, asn);
      }
    }
    return Buffer.from(_nodeForge.default.asn1.toDer(p7.toAsn1()).getBytes(), 'binary');
  }
}
exports.P12Signer = P12Signer;