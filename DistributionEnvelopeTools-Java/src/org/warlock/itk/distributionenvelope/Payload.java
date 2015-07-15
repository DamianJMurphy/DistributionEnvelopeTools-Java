/*
Copyright 2012 Damian Murphy <murff@warlock.org>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */

package org.warlock.itk.distributionenvelope;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.UUID;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.commons.codec.binary.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.warlock.util.CfHNamespaceContext;
import org.warlock.util.dsig.SimpleKeySelector;
import org.xml.sax.InputSource;
/** 
 * Representation of a payload plus its metadata from the distribution envelope manifest.
 *
 * @author Damian Murphy <murff@warlock.org>
 */
public class Payload {
    
    private static final int UNCOMPRESSBUFFERSIZE = 10240;
    private static final int AESKEYSIZE = 256;
    private static final int DATAENCIPHERMENTUSAGE = 3;
    private static final int KEYENCIPHERMENTUSAGE = 2;

    private static final int IVLENGTH = 16;
    
    /**
     * AES with CBC used because it is specified in the "Best Practice" document,
     * PKCS5 padding is specified because it is interoperable with .Net (though
     * .Net calls it PKCS7 they are interchangeable for block ciphers with a 64
     * bit block size.
     */
    private static final String SYMMETRICENCRYPTIONALGORITHM = "AES/CBC/PKCS5Padding";
    
    private String manifestId = null;
    private String mimeType = null;
    private String profileId = null;
    private boolean base64 = false;
    private boolean compressed = false;
    private boolean encrypted = false;
    
    /**
     * This is set false here for the default behaviour that requires certificates
     * to have been issued with a "key usage" extension. It is NOT unset anywhere,
     * and there is no configuration setting to make it true (and hence to accept
     * certificates that have no key usage extension). If there is a need in a 
     * particular case to accept such certificates, change this here as a compile
     * time option - or modify the code to support a configuration option.
     */
    // private boolean allowNonUsageCertificates = false;
    
    // FOR TESTING - we're testing functionality without the "KeyUsage" extension
    // in the certificates, so allow certificates without the extension for now.
    //
    private boolean allowNonUsageCertificates = true;
    private boolean unmunged = false;

    private String payloadBody = null;

    private ArrayList<X509Certificate> readerCerts = new ArrayList<X509Certificate>();
    private String encryptedContent = null;
    private HashMap<String, String> receivedReaders = null;
    /**
     * Public Payload constructor called by senders making a DistributionEnvelope.
     * 
     * @param m Payload MIME type.
     */     
    public Payload(String m) {
        manifestId = "uuid_" + UUID.randomUUID().toString().toUpperCase();
        mimeType = m;
    }

    /**
     * Internal Payload constructor called by the DistributionEnvelopeHelper when
     * parsing received XML.
     */    
    Payload(String id, String m, String p, String b, String c, String e) {
        manifestId = id;
        mimeType = m;
        if (p != null && p.length() > 0) {
                profileId = p;
        }
        base64 = (b.contentEquals("true"));
        compressed = (c.contentEquals("true"));
        encrypted = (e.contentEquals("true"));
    }
    
    /**
     * Called by the DistributionEnvelopeHelper to write base64 encoded ciphertext
     * for the payload.
     * 
     * @param ec 
     */
    void setEncryptedContent(String ec) {
        encryptedContent = ec;
        receivedReaders = new HashMap<String,String>();
    }
    
    /**
     * Called by the DistributionEnvelopeHelper to record an encrypted symmetric
     * key, and the associated public key name. Note that this is internal and
     * expects to be called from the helper, because it assumes that the helper
     * has set the encrypted content first (which creates the HashMap into which
     * the reader details are written).
     * 
     * @param n Public key name
     * @param k Base64 encrypted symmetric key
     */
    void addReceivedReader(String n, String k) {
        receivedReaders.put(n, k);
    }
    
    /**
     * Add an X.509v3 certificate for a recipient.
     * 
     * @param r 
     */
    public void addReaderCertificate(X509Certificate r) 
            throws Exception
    { 
        if (r == null) {
            throw new Exception("Null certificate");
        }
        // Date range check against current date and time
        //
        r.checkValidity();
        
        // Allowed use check. Need to check that the certificate is issued
        // for usages that include "data encipherment". By default, require a
        // "key usage" extension unless the compile-time "allowNonUsageCertificates"
        // has been set.
        //
        // This is here where other certificate checking steps are handled elsewhere,
        // because the "data encipherment" usage is a specific usage type for the
        // content encryption.
        //
        boolean[] usage = r.getKeyUsage();
        if (usage != null) {
            if (!usage[DATAENCIPHERMENTUSAGE]) {
                throw new Exception("Certificate " + r.getSubjectDN().getName() + " not valid for data encipherment");
            }
        } else {
            if (!allowNonUsageCertificates) {
                throw new Exception("Certificate " + r.getSubjectDN().getName() + " has no key usage extension.");
            }
        }
// This is included but commented out specifically to make the point that
// section 4.2.1.3, "Key Usage" in RFC2459 says that the "key encipherment"
// usage is for key management, so it isn't relevant here.
//
//        if (!usage[KEYENCIPHERMENTUSAGE]) {
//            throw new Exception("Certificate " + r.getSubjectDN().getName() + " not valid for key encipherment");
//        }
        encrypted = true;
        readerCerts.add(r); 
    }

    /**
     * Encrypt the payload content, but sign it using the given PrivateKey and
     * X509Certificate using an enveloping signature, before encrypting.
     * 
     * @param pk
     * @param cert
     * @throws Exception 
     */
    public void encrypt(PrivateKey pk, X509Certificate cert)
            throws Exception
    {
        if (readerCerts.isEmpty()) {
            throw new Exception("No recipient public keys");
        }
        if (payloadBody == null) {
            throw new Exception("Attempt to encrypt empty content");
        }
        signPayload(pk, cert);
        doEncryption();
    }
    
    /** 
     * Sign the payloadBody as-is. Note that this is going to be encrypted anyway
     * so we avoid any incompatibilities due to canonicalisation, and we don't
     * care if the payloadBody is text, compressed and so on. Re-writes payloadBody
     * with a serialised XML Digital Signature "Signature" element containing an
     * enveloping signature, or throws an exception to signal failure. 
     * 
     * @param pk
     * @param cert
     * @throws Exception 
     */
    private void signPayload(PrivateKey pk, X509Certificate cert)
            throws Exception
    {   
        if ((pk == null) || (cert == null)) {
            throw new Exception("Null signing material");
        }
        cert.checkValidity();
        
        XMLSignatureFactory xsf = XMLSignatureFactory.getInstance("DOM");
        Reference ref = null;
        String objectRef = "uuid" + UUID.randomUUID().toString();
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = null;
        DOMStructure payloadContent = null;
        if (compressed || base64 || !mimeType.contains("xml")) {
            ref = xsf.newReference("#" + objectRef, xsf.newDigestMethod(DigestMethod.SHA1, null));
            doc = dbf.newDocumentBuilder().newDocument();
            payloadContent = new DOMStructure(doc.createTextNode(payloadBody));            
        } else {
            Transform t = xsf.newTransform("http://www.w3.org/2001/10/xml-exc-c14n#" , (TransformParameterSpec)null);
            ref = xsf.newReference("#" + objectRef, xsf.newDigestMethod(DigestMethod.SHA1, null), Collections.singletonList(t), null, null);            
            doc = dbf.newDocumentBuilder().parse(new InputSource(new StringReader(payloadBody)));
            payloadContent = new DOMStructure(doc.getDocumentElement());
        }
        XMLObject payloadObject = xsf.newXMLObject(Collections.singletonList(payloadContent), objectRef, null, null);
        SignedInfo si = xsf.newSignedInfo(xsf.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
                (C14NMethodParameterSpec)null), 
                xsf.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
                Collections.singletonList(ref));
        
        KeyInfoFactory kif = xsf.getKeyInfoFactory();
        ArrayList<Object> x509content = new ArrayList<Object>();
        x509content.add(cert);
        X509Data xd = kif.newX509Data(x509content);
        
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));
        XMLSignature signature = xsf.newXMLSignature(si, ki, Collections.singletonList(payloadObject), null, null);
        DOMSignContext dsc = new DOMSignContext(pk, doc);
        signature.sign(dsc);
        StringWriter sw = new StringWriter();
        StreamResult sr = new StreamResult(sw);
        Transformer tx = TransformerFactory.newInstance().newTransformer();
        tx.transform(new DOMSource(doc), sr);
        if(sw.toString().indexOf("<?xml ") == 0){
            payloadBody = sw.toString().substring(sw.toString().indexOf("?>")+"?>".length());
        } else {
            payloadBody = sw.toString();
        }
    }
    
    /**
     * Encrypt the payload content for the given reader certificates. According to 
     * XML Encryption specification and the ITK details.
     * 
     * @throws Exception If there are no reader certificates, if the content is empty, or if something else goes wrong in the process.
     */
    public void encrypt()
            throws Exception
    {
        if (readerCerts.isEmpty()) {
            throw new Exception("No recipient public keys");
        }
        if (payloadBody == null) {
            throw new Exception("Attempt to encrypt empty content");
        }
        doEncryption();
    }
    
    /**
     * Common payload content encryption method which is called after sanity
     * checks, and after any content signing is performed.
     * 
     * @throws Exception 
     */
    private void doEncryption()
            throws Exception
    {
        // Make the one-time symmetric key, and encrypt the payload content using it.
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
	kgen.init(AESKEYSIZE);
	SecretKey key = kgen.generateKey();
        String cipherData = doAESEncryption(key);
        
        // Start constructing the XML Encryption "EncryptedData" element. The main 
        // payload encryption is AES-256/CBC
        //
        StringBuilder sb = new StringBuilder("<xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">");
        sb.append("<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"/>");

        // And then the KeyInfo which is the symmetric key byte[] encrypted for each
        // reader certificate.
        //
        sb.append("<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">");
        byte[] keyMaterial =  key.getEncoded();
        for (X509Certificate x : readerCerts) {
            sb.append(doRSASymmetricKeyEncryption(x, keyMaterial));
        }
        sb.append("</ds:KeyInfo>");
        sb.append(cipherData);
        sb.append("</xenc:EncryptedData>");
        
        // Set the payloadBody to the EncryptedData, and the "encrypted" flag to "true".
        // Note that "base64" and "compressed" apply to the *cleartext*, and so are not
        // altered by this operation. The same goes for the mime type. Receiving systems
        // that decrypt the payload will need these other data set correctly in order to
        // convert the encrypted and possibly otherwise-processed content into something
        // they can use.
        //
        payloadBody = sb.toString();
        encrypted = true;
        
        // Make sure we overwrite the key byte[] before we leave, and mark the
        // one-time secret key null.
        //
        for (int i = 0; i < keyMaterial.length; i++) {
            keyMaterial[i] = 0;
        }
        key = null;
    }

    /**
     * Creates an XML Encryption "EncryptedKey" element using. Note that this does
     * NOT check the signing chain of the given certificate - the caller is responsible
     * for doing that since it makes assumptions about the availability of verification
     * and CRL information that the DistributionEnvelopeTools package cannot know about.
     * 
     * Note also that this made to encrypt 256 bit AES-256 keys. The Cipher.doFinal() call
     * used will handle this data size, but it has a maximum of 256 bytes - so if the code
     * is used for symmetric keys of 256 bytes or larger, it will need to be re-factored to
     * loop through the larger key.
     * 
     * @param cert X.509v3 certificate containing the reader's public key
     * @param k Symmetric key material
     * @return Serialised "EncryptedKey" element.
     * @throws Exception If something goes wrong.
     */
    private String doRSASymmetricKeyEncryption(X509Certificate cert, byte[] k)
            throws Exception
    {
        // Encrypt the symmetric key using the given certificate...
        //
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, cert);
        byte[] c = cipher.doFinal(k);
        
        // ... then base64 encode the ciphertext and store it in an EncryptedKey
        // element, noting that the key is encrypted using RSA 1.5
        //
        Base64 b64 = new Base64();
        byte[] encryptedKey = b64.encode(c);            
        StringBuilder sb = new StringBuilder("<xenc:EncryptedKey><EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-1_5\"/>");
        
        // Record the "reader" using the subject Distinguished Name of the given certificate,
        // and store it in the "KeyName" element. Receivers will use this to match "their" copy
        // of the encrypted symmetric key, with the private key they hold.
        //
        sb.append("<ds:KeyInfo><ds:KeyName>");
        sb.append(cert.getSubjectDN().getName());
        sb.append("</ds:KeyName></ds:KeyInfo>");
        sb.append("<xenc:CipherData><xenc:CipherValue>");
        sb.append(new String(encryptedKey));
        sb.append("</xenc:CipherValue></xenc:CipherData>");
        sb.append("</xenc:EncryptedKey>");
        return sb.toString();        
    }
    
    /**
     * Encrypt the payload content using AES-256. NOTE: The stock JDK/JRE DOES NOT SHIP
     * with an AES implementation that will handle 256 bit keys: this needs to be
     * obtained separately - however developers in the UK should have no trouble
     * obtaining the "Unlimited Strength Jurisdiction Policy" files required to
     * do AES-256. 
     * Return the encrypted data as a String representation of an
     * XML Encryption "CipherData" element with the base64 encoded ciphertext.
     * 
     * @param key Symmetric secret key
     * @return String containing a serialised CipherData element with the encrypted payload base64 encoded.
     * @throws Exception 
     */
    private String doAESEncryption(SecretKey key)
            throws Exception
    {
        Cipher cipher = Cipher.getInstance(SYMMETRICENCRYPTIONALGORITHM);
        // The IV is made from the first 16 bytes of the payload manifest id.
        //
        IvParameterSpec iv = getInitialisationVector();
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] c = cipher.doFinal(payloadBody.getBytes("UTF-8"));
        Base64 b64 = new Base64();
        byte[] content = b64.encode(c);            
        StringBuilder sb = new StringBuilder("<xenc:CipherData><xenc:CipherValue>");
        sb.append(new String(content));
        sb.append("</xenc:CipherValue></xenc:CipherData>");
        return sb.toString();        
    }
    
    /**
     * Checks to see if an encrypted payload has a symmetric key encrypted for
     * the given reader key name.
     * 
     * @param s Key name to check.
     * @return True if it does, false if not or there are no symmetric key encryptions.
     */
    public boolean hasKeyForReader(String s) {
        if (receivedReaders == null) {
            return false;
        }
        return receivedReaders.containsKey(s);
    }
    
    /**
     * Make an IV for the AES encryption. This needs to be the same for both the
     * encryption and decryption and, if unspecified, the Cipher will make a new one
     * in each case - so the content won't be able to be decrypted. Use the first 
     * 16 bytes of the payload's manifest id as an IV.
     * 
     * @return IvParameter spec made from the data as described.
     * @throws Exception 
     */
    private IvParameterSpec getInitialisationVector()
            throws Exception
    {        
        byte[] iv = new byte[IVLENGTH];
        for (int i = 0; i < IVLENGTH; i++) {
            iv[i] = 0;
        }
        int j = (manifestId.startsWith("uuid")) ? 4 : 0;
        byte[] id = manifestId.getBytes("UTF-8");
        for (int i = 0; i < manifestId.length(); i++ ) {
            if (i == IVLENGTH)
                break;
            iv[i] = id[i + j];
        }
        return new IvParameterSpec(iv);
    }
    
    /**
     * Returns the payload content as a string - this is only suitable for "stringable"
     * payloads (determined by MIME type) and will throw an exception otherwise. Any
     * compression or base64 decoding that is required will be handled as indicated
     * by the relevant flags in the Payload instance.
     * 
     * @param keyname Subject DN of the certificate containing the public key, used to
     * identify which encrypted symmetric key needs to be decrypted to access the content.
     * @param privatekey Private key corresponding to the public key with the given Subject DN
     * @return Decrypted and decoded text content, as a string.
     * @throws Exception 
     */
    public String decryptTextContent(String keyname, PrivateKey privatekey)
            throws Exception
    {
        byte[] decrypted = decrypt(keyname, privatekey);
        if (decrypted == null) {
            return "";
        }
        String p = new String(decrypted);
        return getTextContent(p);
    }

    /**
     * Returns the payload as a byte array. This does no checking of MIME type and
     * is therefore suitable for binary content that has no string representation.
     * Handles de-compression and base64 decoding as indicates by the flags in the
     * payload.
     * @param keyname Subject DN of the certificate containing the public key, used to
     * identify which encrypted symmetric key needs to be decrypted to access the content.
     * @param privatekey Private key corresponding to the public key with the given Subject DN
     * @return Decrypted and decoded text content, as a byte array.
     * @throws Exception 
     */
    public byte[] decryptRawContent(String keyname, PrivateKey privatekey)
            throws Exception
    {
        byte[] decrypted = decrypt(keyname, privatekey);
        if (decrypted == null) {
            return null;
        }
        String p = new String(decrypted);
        return demungeRawContent(p);
    }
    
    /**
     * Use the given private key and name to decrypt the payload body and return
     * it as a string. The decrypted content is NOT RETAINED in this instance of
     * Payload.
     * 
     * @param keyname Name of the public key used to encrypt the symmetric key
     * @param privatekey Associated private key. The caller is responsible for passwords and other retrieval operations
     * @return Decrypted payload as a byte array. It is up to the caller to use the various payload flags and MIME type to determine what it wants to do with the decrypt.
     * @throws Exception If anything goes wrong in the process.
     */
    private byte[] decrypt(String keyname, PrivateKey privatekey)
            throws Exception
    {
        if (!encrypted) {
            throw new Exception("Not encrypted");
        }
        if (!hasKeyForReader(keyname)) {
            throw new Exception("No such key");
        }
        
        // Base64-decode the encrypted symmetric key for the given keyname (note the 
        // point above, under encryption, about the maximum size of this symmetric key
        // to do this operation with a single call to doFinal()).
        //
        Base64 b64 = new Base64();
        byte[] ekey = b64.decode(receivedReaders.get(keyname).getBytes("UTF-8"));        
        Cipher keydecrypt = Cipher.getInstance("RSA");
        keydecrypt.init(Cipher.DECRYPT_MODE, privatekey);
        byte[] symmetrickey = keydecrypt.doFinal(ekey);
        
        // Then use the decrypted symmetric key to decrypt the payload content.
        // This must use the same Initialisation Vector as the encryption operation,
        // so make the IV from the first 16 bytes of the manifest id. The payload
        // ciphertext will need base64 decoding first.
        //
        Cipher contentdecrypt = Cipher.getInstance(SYMMETRICENCRYPTIONALGORITHM);
        SecretKeySpec sk = new SecretKeySpec(symmetrickey, "AES");
        IvParameterSpec iv = getInitialisationVector();
        contentdecrypt.init(Cipher.DECRYPT_MODE, sk, iv);
        b64 = new Base64();
        byte[] enc = b64.decode(encryptedContent.getBytes("UTF-8"));
        byte[] decrypted = contentdecrypt.doFinal(enc);
                
        // This method should return the decrypted byte array. It is up to the caller to 
        // check the manifest data - mime type, compressed flag and base64 to determine 
        // what to do with the decrypted data, because generically we don't know what it
        // is or how to handle it here.
        //
        for (int i = 0; i < symmetrickey.length; i++) {
            symmetrickey[i] = 0;
        }
        
        // See if what we have is an enveloping signature. If we do, verify the
        // signature before returning the decrypted object it contains.        
        //
        return checkSignature(decrypted);
    }
 
    /**
     * Handle signed content after decryption. The content is signed and encrypted
     * separately, and when a payload is decrypted it may or may not be signed. This
     * method checks if the payload has been signed: if not it is returned unchanged.
     * If the content has been signed, the signature is verified before the content
     * that was signed, is returned.
     * @param decrypted Decrypted 
     * @return
     * @throws Exception If the signature verification fails.
     */
    private byte[] checkSignature(byte[] decrypted)
            throws Exception
    {
        String tryXml = null;
        try {
            tryXml = new String(decrypted);
        }
        catch (Exception e) {
            return decrypted;
        }
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().parse(new InputSource(new StringReader(tryXml)));
        Element rootElement = doc.getDocumentElement();
        String rname = rootElement.getLocalName();        
        if ((rname == null) || !rname.contentEquals("Signature")) {
            return decrypted;
        }
        String rns = rootElement.getNamespaceURI();
        if ((rns == null) || !rns.contentEquals(CfHNamespaceContext.DSNAMESPACE)) {
            return decrypted;
        }
        // We have a signed payload... Verify as an enveloping signature and return
        // the Object if the signature verifies OK.
        //
        verifySignature(rootElement);
        return getSignatureObject(rootElement);
    }
    
    /**
     * Carries out the cryptographic part of signature verification on a parsed
     * "Signature" element.
     * @param signature
     * @throws Exception 
     */
    private void verifySignature(Element signature)
            throws Exception
    {
        X509Certificate x509 = getCertificate(signature);
        SimpleKeySelector sks = new SimpleKeySelector();
        sks.setFixedKey(x509.getPublicKey());
        DOMStructure sig = new DOMStructure(signature);
        XMLSignatureFactory xsf = XMLSignatureFactory.getInstance("DOM");        
        DOMValidateContext dvc = new DOMValidateContext(sks, signature);
        dvc.setProperty("javax.xml.crypto.dsig.cacheReference", Boolean.TRUE);
        XMLSignature xmlsig = xsf.unmarshalXMLSignature(sig);
        boolean isvalid = xmlsig.validate(dvc);
        if (!isvalid) {
            throw new Exception("Signature invalid");
        }
    }
    
    /**
     * Retrieves the certificate used for an enveloping signature.
     * @param signature
     * @return
     * @throws Exception 
     */
    private X509Certificate getCertificate(Element signature)
            throws Exception
    {
        NodeList nl = signature.getElementsByTagNameNS(CfHNamespaceContext.DSNAMESPACE, "X509Certificate");
        if (nl.getLength() == 0) {
            throw new Exception("Cannot find certificate in signature");
        }
        Element x509cert = (Element)nl.item(0);
        StringBuilder sb = new StringBuilder("-----BEGIN CERTIFICATE-----\n");
        String encodedKey = x509cert.getTextContent();
        sb.append(encodedKey);
        if (encodedKey.charAt(encodedKey.length() - 1) != '\n') {
            sb.append("\n");
        }
        sb.append("-----END CERTIFICATE-----");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate x = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(sb.toString().getBytes()));
        return x;
    }
    
    /**
     * Extracts the content of an "Object" element element of the enveloping 
     * signature - see the W3 XML Encryption specification.
     * @param signature
     * @return
     * @throws Exception 
     */
    private byte[] getSignatureObject(Element signature)
            throws Exception
    {
//        NodeList nl = signature.getElementsByTagNameNS(CfHNamespaceContext.DSNAMESPACE, "Object");
//        if (nl.getLength() == 0) {
//            throw new Exception("Error retrieving object from signature");
//        }
//        String object = ((Element)nl.item(0)).getTextContent();
//        return object.getBytes();
        NodeList nl = signature.getElementsByTagNameNS(CfHNamespaceContext.DSNAMESPACE, "Object");
        if (nl.getLength() == 0) {
            throw new Exception("Error retrieving object from signature");
        }
        StringWriter outfile = new StringWriter();
        StreamResult sr = new StreamResult(outfile);
        Transformer tx = TransformerFactory.newInstance().newTransformer();
        String out;
        Node n = (Node)nl.item(0);
        NodeList subnl = n.getChildNodes();
        Node subn = (Node)subnl.item(0);
        if(subn.hasChildNodes()){
            tx.transform(new DOMSource((Node)subnl.item(0)), sr);
            out = outfile.toString();
            if(out.indexOf("<?xml ") == 0){
                out = out.substring(out.indexOf("?>")+"?>".length());
            }
        } else {
            out = n.getTextContent();
        }

        return out.getBytes();
    }
    
    /**
     * @param prefix Prefix to use for the ITK XML namespace.
     * 
     * @returns String containing the manifestitem element for this payload.
     */     
    public String makeManifestItem(String prefix) 
    {
        StringBuilder sb = new StringBuilder();
        sb.append("<");
        sb.append(prefix);
        sb.append(":manifestitem mimetype=\"");
        sb.append(mimeType);
        sb.append("\"");
        if (profileId != null) {
            sb.append(" profileid=\"");
            sb.append(profileId);
            sb.append("\"");
        }
        sb.append(" base64=\"");
        sb.append(Boolean.toString(base64));
        sb.append("\" compressed=\"");
        sb.append(Boolean.toString(compressed));
        sb.append("\" encrypted=\"");
        sb.append(Boolean.toString(encrypted));
        sb.append("\" id=\"");
        sb.append(manifestId);
        sb.append("\"/>");
        return sb.toString();
    }

    /**
     * Sets the profile id for the manifestitem, this is not validated and it
     * is the caller's responsibility to set the correct value.
     */     
    public void setProfileId(String p) { profileId = p; }
  
    /**
     * Sets and optionally tries to compress the payload body as a string. 
     * 
     * If requested, the method will compress the body, but will only retain
     * the compressed form if a ratio > 1.34 is obtained, to cover the overhead 
     * of base64 encoding the compressed data.
     * 
     * @param b Payload body
     * @param pack Should the method attempt to compress the body.
     */     
    public void setBody(String b, boolean pack) 
            throws Exception
    { 
        payloadBody = b;
        if (!pack) {
            return;
        }
        compressIfViable(payloadBody.getBytes("UTF8"));
    }

    /**
     * Compress the content according to the RFC1952 GZip algorithm. Since 
     * compression produces binary output, to fit
     * into an XML document the output has to be base64 encoded, which results 
     * in a 33% increase in size. So the compressed form is only "accepted" if
     * the attempt results in an overall reduction in size.
     * 
     * @param content
     * @throws Exception 
     */
    private void compressIfViable(byte[] content)
            throws Exception
    {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        GZIPOutputStream gzOut = new GZIPOutputStream(out, UNCOMPRESSBUFFERSIZE);
        gzOut.write(content, 0, content.length);
        gzOut.finish();
        byte[] comp = out.toByteArray();
        double ratio = (double)content.length / (double)comp.length;
        if (ratio > 1.34) {
            Base64 b64 = new Base64();
            comp = b64.encode(comp);            
            payloadBody = new String(comp);
            compressed = true;
        } else {
            compressed = false;            
            if (payloadBody != null) {
                return;
            }
            Base64 b64 = new Base64();
            comp = b64.encode(content);            
            payloadBody = new String(comp);            
            base64 = true;
        }               
    }
    
    /**
     * Sets and optionally tries to compress the payload body as a byte
     * array. In either case the data is base64 encoded. 
     * 
     * If requested, the method will compress the body, but will only retain
     * the compressed form if a ratio > 1.34 is obtained, to cover the overhead 
     * of base64 encoding the compressed data.
     * 
     * @param b Payload body
     * @param pack Should the method attempt to compress the body.
     */     
    public void setContent(byte[] data, boolean pack)
        throws Exception
    {
        if (!pack) {            
            base64 = true;        
            Base64 b64 = new Base64();
            byte[] content = b64.encode(data);
            payloadBody = new String(content);
            return;
        }
        compressIfViable(data);
    }
    
    /**
     * Allows the sender to "manually" set (or unset) the base64 flag,
     * for example where a payload is provided which is already so
     * encoded.
     */ 
    public void setBase64(boolean b) { base64 = b; }
 
    /**
     * Allows the sender to "manually" set (or unset) the compressed flag,
     * for example where a payload is provided which is already compressed.
     */     
    public void setCompressed(boolean c) 
    { 
        compressed = c;
    }
    
    /**
     * Sets the encrypted flag. Reserved for future use.
     */     
    public void setEncrypted(boolean e) { encrypted = e; }      
    
    public boolean isBase64() { return base64; }
    public boolean isCompressed() { return compressed; }
    public boolean isEncrypted() { return encrypted; }
    public boolean isDecoded() { return unmunged; }
    public String getMimeType() { return mimeType; }
    public String getManifestId() { return manifestId; }
    public String getProfileId() { return profileId; }
    public String getPayloadBody() { return payloadBody; }
        
    /**
     * Gets clear-text content as a String, checks
     * @return The content as a string.
     * @throws Exception If the content is encrypted, not representable as a string, or any decoding operations fail.
     */
    public String getContent() 
            throws Exception
    {
        if (encrypted) {
            throw new Exception("Encrypted body");
        }
        return getTextContent(payloadBody);
    }
    
    /**
     * For payload content which is representable as an un-encoded (including
     * base64) string. Checks for and un-does base64 encoding or compression
     * as required.
     * 
     * @param t Content, possibly encoded or compressed.
     * @return Content as a string.
     * @throws Exception If the content is not representable as a string, or if any other decoding process goes wrong.
     */
    private String getTextContent(String t) 
            throws Exception
    { 
        if (!stringable()) {
            throw new Exception("Not stringable - use getRawContent()");
        }
        if (compressed) {
            byte[] uncomp = decompressBody(t);
            return new String(uncomp);
        } else {
            if (base64) {
                Base64 b64 = new Base64();
                return new String(b64.decode(t.getBytes("UTF-8")));                
            }
        }
        return t; 
    }

    /**
     * Return decompressed content.
     * @param t Base64 encoded string containing the compressed content.
     * @return
     * @throws Exception 
     */
    private byte[] decompressBody(String t)
            throws Exception
    {
        byte decoded[] = null;
        Base64 b64 = new Base64();
        decoded = b64.decode(t.getBytes("UTF-8"));
        ByteArrayOutputStream uncomp = new ByteArrayOutputStream();
        GZIPInputStream gzIn = new GZIPInputStream(new ByteArrayInputStream(decoded), UNCOMPRESSBUFFERSIZE);
        byte[] buffer = new byte[UNCOMPRESSBUFFERSIZE];
        int l = -1;
        while ((l = gzIn.read(buffer, 0, UNCOMPRESSBUFFERSIZE)) != -1) {
            uncomp.write(buffer, 0, l);
        }
        gzIn.close();
        return uncomp.toByteArray();                    
    }
    
    /**
     * Returns binary content when not encrypted, with compression and base64 
     * encoding un-done.
     * @return
     * @throws Exception 
     */
    public byte[] getRawContent()
            throws Exception
    {
        if (encrypted) {
            throw new Exception("Encrypted body");
        }
        return demungeRawContent(payloadBody);        
    }
    
    /**
     * Un-do treatments such as compression and base64 encoding.
     * @param t
     * @return
     * @throws Exception 
     */
    private byte[] demungeRawContent(String t) 
            throws Exception
    { 
        if (compressed) {
            return decompressBody(t);
        }
        if (base64) {
            Base64 b64 = new Base64();
            return b64.decode(t.getBytes("UTF-8"));
        }
        return t.getBytes("UTF-8"); 
    }
    
    /**
     * Returns a list of the Subject DN strings of encryption recipients.
     * @return 
     */
    public String[] getEncryptionRecipients() {
        if (!encrypted) {
            return null;
        }
        String[] keyNames = null;        
        return keyNames;
    }
    
    /**
     * Called by DistributionEnvelopeHelper
     */     
    public void setContent(String pb)
            throws Exception
    {
        payloadBody = pb;
    }
    
    /**
     * Is it meanigful to return this content as an un-encoded string ?
     * @return 
     */
    private boolean stringable(){
        // Just make some simple inferences from the MIME type
        //
        if (mimeType == null) return false;
        if (mimeType.startsWith("text")) return true;
        if (mimeType.startsWith("application") && mimeType.toLowerCase().contains("xml")) return true;
        return false;
    }    
}
