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
import java.io.InputStream;
// import java.io.InputStreamReader;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import org.warlock.util.xsltransform.TransformManager;
import org.warlock.itk.util.ITKException;
/** Class to make a distribution envelope, by running an XSL transform which 
 * extracts details needed for routing and
 * logging (addresses, sender identity and address, service and tracking id).
 *
 * @author Damian Murphy <murff@warlock.org>
 */
public class DistributionEnvelopeHelper {
    
    private static final int BUFFERSIZE = 1024;
    private static final String EXTRACT_TRANSFORM = "distribution-envelope-extractor.xslt";
    private static final String EXTRACT_START_DELIMITER = "<!--";
    private static final String EXTRACT_END_DELIMITER = "-->";
    
    private static final String PAYLOAD_EXTRACT_TRANSFORM = "distribution_envelope_payload_extractor.xslt";
    private static final String PAYLOAD_DELIMITER = "#-#-#-#-#-#-#-#-#";
    private static final String PAYLOAD_FIELD_DELIMITER = "####";
    
    private static final String ENCRYPTEDDATA_EXTRACT_TRANSFORM = "encrypted_data_extractor.xslt";
    
    private static DistributionEnvelopeHelper me = new DistributionEnvelopeHelper();
    private static Exception initialException = null;


    private static X509CRL crl = null;
    
    private DistributionEnvelopeHelper() {
        try {
            // Load the XSLT transform that gets relevant information from the distribution
            // envelope
            //
            TransformManager t = TransformManager.getInstance();
            InputStream is = getClass().getResourceAsStream(EXTRACT_TRANSFORM);
            t.addTransform(EXTRACT_TRANSFORM, is);
            
            is = getClass().getResourceAsStream(PAYLOAD_EXTRACT_TRANSFORM);
            t.addTransform(PAYLOAD_EXTRACT_TRANSFORM, is);
            
            is = getClass().getResourceAsStream(ENCRYPTEDDATA_EXTRACT_TRANSFORM);
            t.addTransform(ENCRYPTEDDATA_EXTRACT_TRANSFORM, is);
            
        }
        catch (Exception e) {
            Logger.getLogger(ITKException.SYSTEM_LOGGER).log(Level.SEVERE, "Failed to initialise distribution envelope transforms", e);
            initialException = e;
        }
    }
    
    /**
     * @returns Singleton DistributionEnvelopeHelper
     * @throws Any initialisation exception
     */     
    public static DistributionEnvelopeHelper getInstance() 
            throws Exception
    {  
        if (initialException != null) {
            throw initialException;
        }
        return me; 
    }

    
    /**
     * Parse the payloads in the given DistributionEnvelope and its manifest
     * 
     * @returns Array of Payload instances
     */     
    public Payload[] getPayloads(DistributionEnvelope d)
            throws Exception
    {
        TransformManager t = TransformManager.getInstance();
        String extract = t.doTransform(PAYLOAD_EXTRACT_TRANSFORM, d.getEnvelope());
        if (extract.startsWith("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")) {
            extract = extract.substring("<?xml version=\"1.0\" encoding=\"UTF-8\"?>".length());
        }
        if(extract.startsWith("\r\n")){
            extract = extract.substring("\r\n".length());
        }
        return splitPayloads(extract);
    }

    public void unpackEncryptedPayload(Payload p)
            throws Exception
    {
        // Run an XSL transform to extract from the PayloadBody:
        //
        // 1. The encrypted keys as N=keyname####K=base64encodedkey pairs
        // 2. A "payload delimiter" (static)
        // 3. The base64 encoded ciphertext
        //
        // Get that as a text string, then split it up and add it to the
        // Payload
        TransformManager t = TransformManager.getInstance();
        String ed = t.doTransform(ENCRYPTEDDATA_EXTRACT_TRANSFORM, p.getPayloadBody());
        String[] parts = ed.split(PAYLOAD_DELIMITER);
        if (parts.length != 2) {
            throw new Exception("Malformed EncryptedData");
        }
        p.setEncryptedContent(parts[1]);
        
        // Parse out the encrypted symmetric keys and add them to the Payload
        //
        String r[] = parts[0].split(PAYLOAD_FIELD_DELIMITER);
        String keyname = null;
        String encryptedkey = null;
        for (int i = 1; i < r.length; i++) {
            if (r[i].startsWith("KEYNAME:=")) {
                keyname = r[i].substring(9);
                i++;
                if (r[i].startsWith("ENCRYPTEDKEY:=")) {
                    encryptedkey = r[i].substring(14);
                    p.addReceivedReader(keyname, encryptedkey);
                } else {
                    throw new Exception("Malformed EncryptedData - encrypted key value expected but not found");
                }
            } else {
                throw new Exception("Malformed EncryptedData - key name expected but not found");
            }
        }
    }
    
    private Payload[] splitPayloads(String s) 
            throws Exception
    {
        String id = null;
        String mt = null;
        String pid = null;
        String b64 = null;
        String cmpd = null;
        String enc = null;
        String pbdy = null;
        String[] parts = s.split("#-#-#-#-#-#-#-#-#");
        Payload[] payloads = new Payload[parts.length];
        int i = 0;
        for (String p : parts) {
            String fields[] = p.split("####");
            for (String f : fields) {
                String[] element = f.split(":=");
                if (element[0].contentEquals("ID")) {
                    id = element[1];
                    continue;
                }
                if (element[0].contentEquals("MIMETYPE")) {
                    mt = element[1];
                    continue;
                }
                if (element[0].contentEquals("PROFILEID")) {
                    if (element.length == 2) {
                        pid = element[1];
                    }
                    continue;
                }
                if (element[0].contentEquals("BASE64")) {
                    if (element.length == 2) {
                        b64 = element[1];
                    } else {
                        b64 = "false";
                    }
                    continue;
                }
                if (element[0].contentEquals("COMPRESSED")) {
                    if (element.length == 2) {
                        cmpd = element[1];
                    } else {
                        cmpd = "false";
                    }
                    continue;
                }
                if (element[0].contentEquals("ENCRYPTED")) {
                    if (element.length == 2) {
                        enc = element[1];
                    } else {
                        enc = "false";
                    }
                    continue;
                }
                if (element[0].contentEquals("PAYLOADBODY")) {
                    try {
                        pbdy = element[1];
                    }
                    catch (ArrayIndexOutOfBoundsException ea) {
                        throw new Exception("Failed to parse payloads: cannot find all declared payloads", ea);
                    }
                    continue;
                }                
            }
            payloads[i] = new Payload(id, mt, pid, b64, cmpd, enc);
            payloads[i].setContent(pbdy);
            i++;
        }
        return payloads;
    }

    /**
     * Parse the DistributionEnvelope XML in the given string.
     */     
    public DistributionEnvelope getDistributionEnvelope(String s)
            throws Exception
    {
        TransformManager t = TransformManager.getInstance();
        String extract = t.doTransform(EXTRACT_TRANSFORM, s);
        return splitExtract(extract);
    }
    
    /**
     * Parse the DistributionEnvelope XML read from the given InputStream
    */    
    public DistributionEnvelope getDistributionEnvelope(InputStream is)
            throws Exception
    {        
        TransformManager t = TransformManager.getInstance();        
        String extract = t.doTransform(EXTRACT_TRANSFORM, is);
        return splitExtract(extract);
    }
    
    private DistributionEnvelope splitExtract(String s)
            throws Exception
    {
        // The argument is a string containing an XML comment with the
        // extracted data, followed by the distribution envelope. Make
        // an instance of DistributionEnvelope. Split off the "distribution
        // envelope" XML, then break up the comment string and populate the
        // DistributionEnvelope instance we just created.
        
        DistributionEnvelope d = new DistributionEnvelope();
        int ee = s.indexOf(EXTRACT_END_DELIMITER);
        if (ee == -1) {
            throw new Exception("Failed DistributionEnvelope extract - envelope not found");
        }
        int ds = ee + EXTRACT_END_DELIMITER.length();
        String env = s.substring(ds);
        if ((env == null) || (env.trim().length() == 0)) {
            throw new Exception("Failed DistributionEnvelope extract - zero-length envelope");
        }
        d.setDistributionEnvelope(env);
        int es = s.indexOf(EXTRACT_START_DELIMITER);
        if (es == -1) {
            throw new Exception("Failed DistributionEnvelope extract - extract not found");
        }
        es += EXTRACT_START_DELIMITER.length();
        String extract = s.substring(es, ee);
        
        // Make the regex patterns to split up the extract
        Pattern lineDelimiter = Pattern.compile("\\!");
        Pattern fieldDelimiter = Pattern.compile("#");
        
        // Split into lines and see what goes where...
        String[] lines = lineDelimiter.split(extract);
        ArrayList<Address> addresses = new ArrayList<Address>();
        ArrayList<Identity> audit = new ArrayList<Identity>();
        Address sender = null;
        for (String l : lines) {
            String[] fields = fieldDelimiter.split(l);
            // See what sort of line it is and do the appropriate thing
            if (fields[0].contentEquals("R")) {
                Address a = null;
                if (fields.length > 1) {
                    a = (Address)makeEntity(true, fields);                    
                    d.setSender(a);
                }
                continue;
            }
            if (fields[0].contentEquals("S")) {
                if (fields.length == 2) {
                    d.setService(fields[1]);
                }                
                continue;
            }            
            if (fields[0].contentEquals("T")) {
                if (fields.length == 2) {
                    d.setTrackingId(fields[1]);
                }
                continue;
            }
            if (fields[0].contentEquals("A")) {
                Address a = (Address)makeEntity(true, fields);
                addresses.add(a);
                continue;
            }
            if (fields[0].contentEquals("I")) {
                Identity i = (Identity)makeEntity(false, fields);
                audit.add(i);
                continue;
            }
            if (fields[0].contentEquals("H")) {
                if (fields.length > 1) {
                    try {
                        d.addHandlingSpecification(fields[1], fields[2]);
                    }
                    catch (ArrayIndexOutOfBoundsException e) {
                        d.addHandlingSpecification(fields[1], "");
                    }
                }
            }
        }
        Address addr[] = addresses.toArray(new Address[addresses.size()]);
        Identity ids[] = audit.toArray(new Identity[audit.size()]);
        d.setTo(addr);
        d.setAudit(ids);
        return d;
    }
    
    private Entity makeEntity(boolean addr, String[] f) 
            throws Exception
    {
        Entity e = null;
        if (addr) {
            if (f[1].length() > 0) {
                e = new Address(f[2], f[1]);
            } else {
                e = new Address(f[2]);
            }            
        } else {
            if (f[1].length() > 0) {
                e = new Identity(f[2], f[1]);
            } else {
                e = new Identity(f[2]);
            }            
        }        
        return e;
    }
}
