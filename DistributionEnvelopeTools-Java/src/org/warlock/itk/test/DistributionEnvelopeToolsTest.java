/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.warlock.itk.test;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.BufferedReader;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import org.warlock.itk.distributionenvelope.*;
import org.apache.commons.codec.binary.Base64;
/**
 *
 * @author DAMU2
 */
public class DistributionEnvelopeToolsTest {

    private static final String CERT1 = "test102.crt";
    private static final String CERT2 = "test108.crt";
    private static final String KEY1 = "test102.pfx";
    private static final String KEY2 = "test108.pfx";
    private static X509Certificate cert1 = null;
    private static X509Certificate cert2 = null;
    private static RSAPrivateKey    rsa1 = null;
    private static RSAPrivateKey    rsa2 = null;
    private static KeyStore ks1 = null;
    private static KeyStore ks2 = null;

    
    private static final String SIGNINGKEY = "test116.pfx";
    private static X509Certificate signingCert = null;
    private static RSAPrivateKey signingKey = null;
    
    private static void loadCerts() {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            FileInputStream fis = new FileInputStream(CERT1);
            cert1 = (X509Certificate)cf.generateCertificate(fis);
            fis = new FileInputStream(CERT2);
            cert2 = (X509Certificate)cf.generateCertificate(fis);            
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private static void loadKeys() {
        // TODO: Read the key files into PKCS8EncodedKeySpec instances (as byte[])
        // and then use an "RSA" KeyFactory.generatePrivateKey() from the spec to make
        // the keys. Check how we get passwords into the operation. Passwords are "111test"
        // in all cases.
        //
        // NO. ACTUALLY WANT TO USE EncryptedPrivateKeyInfo
        try {            
            char[] password = {'1','1','1','t','e','s','t'};
            ks1 = KeyStore.getInstance("PKCS12");
            ks2 = KeyStore.getInstance("PKCS12");
            FileInputStream fis = new FileInputStream(KEY1);
            ks1.load(fis, password);
            KeyStore.PasswordProtection p = new KeyStore.PasswordProtection(password);
            rsa1 = (RSAPrivateKey)(((KeyStore.PrivateKeyEntry)ks1.getEntry("1", p)).getPrivateKey());
            fis = new FileInputStream(KEY2);
            ks2.load(fis, password);
            rsa2 = (RSAPrivateKey)(((KeyStore.PrivateKeyEntry)ks2.getEntry("2", p)).getPrivateKey());
            
            KeyStore sks = KeyStore.getInstance("PKCS12");
            fis = new FileInputStream(SIGNINGKEY);
            sks.load(fis, password);
            signingKey = (RSAPrivateKey)(((KeyStore.PrivateKeyEntry)sks.getEntry("3", p)).getPrivateKey());
            signingCert = (X509Certificate)sks.getCertificate("3");
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        
    }
        
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {

        loadKeys();
        loadCerts();        
        if (args[0].contentEquals("read")) {
            String f = args[1];
            try {
                String inde = load(f);
                DistributionEnvelopeHelper helper = DistributionEnvelopeHelper.getInstance();
                DistributionEnvelope de = helper.getDistributionEnvelope(inde);
                Payload[] p = helper.getPayloads(de);
                if (p[0].isEncrypted()) {
                    helper.unpackEncryptedPayload(p[0]);
                    if (p[0].hasKeyForReader("CN=test102.oneoneone.nhs.uk, OU=ITK Accreditation Services, O=National Integration Centre")) {
                        String firstpayload = p[0].decryptTextContent("CN=test102.oneoneone.nhs.uk, OU=ITK Accreditation Services, O=National Integration Centre", rsa1);
//                        Base64 b64 = new Base64();
//                        byte[] x2 = b64.decode(firstpayload);
//                        String s2 = new String(x2);
//                        System.out.println(s2);
                        System.out.println(firstpayload);
                    }
                } else {
                    String x0 = p[0].getContent();
//                    String x1 = p[1].getContent();
                    System.out.println("hold");
                }                
                // String x = p[1].getPayloadBody();
                System.out.println("hold");
            }
            catch (Exception e){
                e.printStackTrace();
            }
        }
        if (args[0].contentEquals("write")) {            
            DistributionEnvelope d = DistributionEnvelope.newInstance();
            try {
                d.addRecipient(null, "test:address:one");
                d.addRecipient("1.2.826.0.1285.0.2.0.107", "123456789012");
                d.addIdentity("1.2.826.0.1285.0.2.0.107", "99999999999");
                d.addSender(null, "test:address:two");
                d.setService("java:test:service");
                d.setInteractionId("test_interaction_UK01");
                for (int i = 1; i < args.length; i++) {
                       // Álternate MIME type and file name
                        String mt = args[i++];
                        String file = args[i];
                        String body = null;
                        byte[] content = null;
                        Payload p = new Payload(mt);
                        boolean pack = (i != 2);
                        pack = true;
                        if (mt.contains("xml")) {
                            body = load(file);                           
                            if (!pack) {
                                p.setProfileId("itk:test:profile-id-v1-0");
                            }
                            p.setBody(body, pack);
                        } else {
                            content = binaryLoad(file);
                            p.setContent(content, pack);
                        }
                        d.addPayload(p);
                        p.addReaderCertificate(cert1);
//                        p.addReaderCertificate(cert2);
//                        p.encrypt();
                        p.encrypt(signingKey, signingCert);
                }
                String expout = d.toString();
                System.out.println(expout);
            }
            catch (Exception e) {
                e.printStackTrace();
            }
        }
        
    }
    
    public static byte[] binaryLoad(String fname)
            throws Exception
    {
        byte[] file = null;
        File f = new File(fname);
        int l = (int)f.length();
        file = new byte[l];
        int r = -1;
        int ptr = 0;
        FileInputStream fis = new FileInputStream(f);
        while((r = fis.read(file, ptr, l)) != -1) {
            ptr += r;
            if (ptr == l) {
                break;
            }
        }
        fis.close();
        return file;
    }
    
    public static String load(String fname) 
            throws Exception
    {
        BufferedReader br = new BufferedReader(new FileReader(fname));
        StringBuilder sb = new StringBuilder();
        String line = null;
        while ((line = br.readLine()) != null) {
            sb.append(line);
            sb.append("\r");
        }
        br.close();
        return sb.toString();
    }
}
