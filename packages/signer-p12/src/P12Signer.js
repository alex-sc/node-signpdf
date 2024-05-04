import forge, {asn1} from 'node-forge';
import {convertBuffer, SignPdfError, Signer} from '@signpdf/utils';
import jsrsasign from 'jsrsasign';
import axios from 'axios';

function timestampToAsn1(timeStampToken) {
    // Timestamp unsigned attribute
    const timestampValue = forge.asn1.create(
        forge.asn1.Class.UNIVERSAL,
        forge.asn1.Type.SET,
        true,
        [timeStampToken],
    );

    return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        // AttributeType
        asn1.create(
            asn1.Class.UNIVERSAL,
            asn1.Type.OID,
            false,
            asn1.oidToDer('1.2.840.113549.1.9.16.2.14').getBytes(),
        ),
        timestampValue,
    ]);
}

const tsa = async ({tsaUrl, signature}) => {
    // Generate SHA256 hash from signature content for TSA
    const md = forge.md.sha256.create();
    md.update(signature);
    const digest = md.digest().getBytes();

    const request = new jsrsasign.asn1.tsp.TimeStampReq({
        messageImprint: {alg: 'sha256', hash: Buffer.from(digest, 'binary').toString('hex')},
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

export class P12Signer extends Signer {
    /**
     * @param {Buffer | Uint8Array | string} p12Buffer
     * @param {SignerOptions} additionalOptions
     */
    constructor(p12Buffer, additionalOptions = {}) {
        super();

        const buffer = convertBuffer(p12Buffer, 'p12 certificate');

        this.options = {
            asn1StrictParsing: false,
            passphrase: '',
            ...additionalOptions,
        };
        this.cert = forge.util.createBuffer(buffer.toString('binary'));
    }

    /**
     * @param {Buffer} pdfBuffer
     * @param {Date | undefined} signingTime
     * @returns {Promise<Buffer>}
     */
    async sign(pdfBuffer, signingTime = undefined) {
        if (!(pdfBuffer instanceof Buffer)) {
            throw new SignPdfError(
                'PDF expected as Buffer.',
                SignPdfError.TYPE_INPUT,
            );
        }

        // Convert Buffer P12 to a forge implementation.
        const p12Asn1 = forge.asn1.fromDer(this.cert);
        const p12 = forge.pkcs12.pkcs12FromAsn1(
            p12Asn1,
            this.options.asn1StrictParsing,
            this.options.passphrase,
        );

        // Extract safe bags by type.
        // We will need all the certificates and the private key.
        const certBags = p12.getBags({
            bagType: forge.pki.oids.certBag,
        })[forge.pki.oids.certBag];
        const keyBags = p12.getBags({
            bagType: forge.pki.oids.pkcs8ShroudedKeyBag,
        })[forge.pki.oids.pkcs8ShroudedKeyBag];

        const privateKey = keyBags[0].key;
        // Here comes the actual PKCS#7 signing.
        const p7 = forge.pkcs7.createSignedData();
        // Start off by setting the content.
        p7.content = forge.util.createBuffer(pdfBuffer.toString('binary'));

        // Then add all the certificates (-cacerts & -clcerts)
        // Keep track of the last found client certificate.
        // This will be the public key that will be bundled in the signature.
        let certificate;
        Object.keys(certBags).forEach((i) => {
            const {publicKey} = certBags[i].cert;

            p7.addCertificate(certBags[i].cert);

            // Try to find the certificate that matches the private key.
            if (privateKey.n.compareTo(publicKey.n) === 0
                && privateKey.e.compareTo(publicKey.e) === 0
            ) {
                certificate = certBags[i].cert;
            }
        });

        if (typeof certificate === 'undefined') {
            throw new SignPdfError(
                'Failed to find a certificate that matches the private key.',
                SignPdfError.TYPE_INPUT,
            );
        }

        // Add a sha256 signer. That's what Adobe.PPKLite adbe.pkcs7.detached expects.
        // Note that the authenticatedAttributes order is relevant for correct
        // EU signature validation:
        // https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/validation
        p7.addSigner({
            key: privateKey,
            certificate,
            digestAlgorithm: forge.pki.oids.sha256,
            authenticatedAttributes: [
                {
                    type: forge.pki.oids.contentType,
                    value: forge.pki.oids.data,
                }, {
                    type: forge.pki.oids.signingTime,
                    // value can also be auto-populated at signing time
                    value: signingTime ?? new Date(),
                }, {
                    type: forge.pki.oids.messageDigest,
                    // value will be auto-populated at signing time
                },
            ],
        });

        // Sign in detached mode.
        p7.sign({detached: true});

        if (this.options.tsaUrl) {
            const forgeSignature = p7.signers[0].signature;

            const timeStampToken = await tsa({
                tsaUrl: this.options.tsaUrl,
                signature: forgeSignature,
            });

            const asn = p7.toAsn1();
            if (timeStampToken) {
                const attrsAsn1 = asn1.create(asn1.Class.CONTEXT_SPECIFIC, 1, true, []);
                attrsAsn1.value.push(timestampToAsn1(timeStampToken));
                dump(attrsAsn1, asn);
            }
        }

        return Buffer.from(forge.asn1.toDer(p7.toAsn1()).getBytes(), 'binary');
    }
}
