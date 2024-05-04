"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.P12Signer = void 0;
var _nodeForge = _interopRequireDefault(require("node-forge"));
var _utils = require("@signpdf/utils");
var fs = require("fs");
var asn1 = require("node-forge").asn1;
var pkcs7 = require("node-forge/lib/pkcs7");
const forge = require("node-forge/lib/forge");
const jsrsasign = require("jsrsasign");
const axios = require("axios");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }
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
      }],
      /*
      unauthenticatedAttributes: [{
        type: "1.2.840.113549.1.9.16.2.14",
        value: "",
      }],
       */
    });

    // Sign in detached mode.
    p7.sign({
      detached: true
    });

    const forgeSignature = p7.signers[0].signature;

    const timeStampToken = await tsa({
      tsaUrl: "http://timestamp.digicert.com/",
      signature: forgeSignature,
    });
    console.log(timeStampToken);


    const asn = p7.toAsn1();
    if (timeStampToken) {
      // [1] IMPLICIT
      var attrsAsn1 = asn1.create(asn1.Class.CONTEXT_SPECIFIC, 1, true, []);
      attrsAsn1.value.push(timestampToAsn1(timeStampToken));
      console.log(attrsAsn1);
      dump(attrsAsn1, asn);
    }
    fs.writeFileSync("signature.asn1", Buffer.from(_nodeForge.default.asn1.toDer(asn).getBytes(), 'binary'));
    return Buffer.from(_nodeForge.default.asn1.toDer(asn).getBytes(), 'binary');
  }
}

/**
 * @param {Asn1} asn
 */
function dump(newAttr, asn, path = [], level = 0) {
  if (Array.isArray(asn.value)) {
    if (asn.value.length === 6 && JSON.stringify(path) === JSON.stringify([16,0,16,17])) {
      console.log(" ".repeat(level) + "" +  asn.tagClass + " " + asn.type + " " + asn.value.length + " children: " + path);
      // 0: version
      // 1: sid
      // 2: digestAlgorithm
      // 3: SignedAttributes
      // 4: signatureAlgorithm
      // 5: signature
      asn.value = [...asn.value, newAttr];
    }
    for (const child of asn.value) {
      const newPath = [...path];
      newPath.push(asn.type);
      dump(newAttr, child, newPath, level + 1);
    }
  } else {
    //console.log(" ".repeat(level) + asn.tagClass + " " + asn.type + " " + Buffer.from(asn.value).toString("hex"));
  }
}

function timestampToAsn1(timeStampToken) {
  // Timestamp unsigned attribute
  const timestampValue = forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.SET,
      true,
      [timeStampToken]
  );

  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    // AttributeType
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
        asn1.oidToDer("1.2.840.113549.1.9.16.2.14").getBytes()),
    timestampValue
  ]);
}

const tsa = async ({ tsaUrl, signature }) => {
  // Generate SHA256 hash from signature content for TSA
  const md = forge.md.sha256.create();
  md.update(signature);
  const digest = md.digest().getBytes();

  const request = new jsrsasign.asn1.tsp.TimeStampReq({
    messageImprint: { alg: 'sha256', hash: Buffer.from(digest, 'binary').toString('hex') },
    certreq: true,
  });
  const requestHex = request.getEncodedHex();
  const tsr = forge.util.hexToBytes(requestHex);

  try {
    const response = await axios({
      method: 'post',
      url: tsaUrl,
      data: Buffer.from(tsr, 'binary'),
      headers: {
        'Content-Type': 'application/timestamp-query',
      },
      responseType: 'arraybuffer',
      responseEncoding: 'binary',
    });
    const responseAsn1 = forge.asn1.fromDer(response.data.toString('binary'));

    // Return the token (it contains cert data)
    return responseAsn1.value[1];
  } catch (error) {
    console.log(error);
    return undefined;
  }
};


exports.P12Signer = P12Signer;