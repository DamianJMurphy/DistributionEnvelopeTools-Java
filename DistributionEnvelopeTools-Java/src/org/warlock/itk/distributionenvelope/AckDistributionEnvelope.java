/*
Copyright 2011 Damian Murphy <murff@warlock.org>

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
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.util.Date;
import java.util.UUID;
import java.text.SimpleDateFormat;
import org.warlock.itk.util.ITKException;
import org.warlock.util.configurator.Configurator;

/** A class to construct and request routing of a generic infrastructure
 * acknowledgment. 
 *
 * @author Damian Murphy <murff@warlock.org>
 */
public class AckDistributionEnvelope 
    extends DistributionEnvelope
{
    
    /** ITK-specification-defined name of the acknowledgment service */
    public static final String SERVICE = "urn:nhs-itk:services:201005:SendInfrastructureAck-v1-0"; 
    protected static final SimpleDateFormat TIMESTAMP = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
    protected String serviceRef = null;
    
    /** Property name for the router's identity, declared in acks and nacks */
    private static final String AUDIT_ID_PROPERTY = "org.warlock.itk.router.auditidentity";
    /** Property name for the router's address */
    private static final String SENDER_PROPERTY = "org.warlock.itk.router.senderaddress";
    private static final String ACK_TEMPLATE = "infrastructure_ack_template.xml.txt";
    
    /** Constructor. Note that construction of this class, and actual making of
     * the acknowledgment message, are separate to allow nack to be implemented 
     * as a subclass of ack.
     * 
     * @param d DistributionEnvelope of the message being acked.
     * @throws ITKException if anything goes wrong.
     */
    public AckDistributionEnvelope(DistributionEnvelope d)
            throws ITKException
    {
        super();
        Address[] a = new Address[1];
        a[0] = d.getSender();
        setTo(a);
        String id = null;
        String snd = null;        
        try {
            Configurator c = Configurator.getConfigurator();
            id = c.getConfiguration(AUDIT_ID_PROPERTY);
            snd = c.getConfiguration(SENDER_PROPERTY);
        }
        catch (Exception e) {
            throw new ITKException("SYST-0000", "Configuration manager exception", e.getMessage());
        }
        Address sndr = new Address(snd);
        Identity[] auditId = new Identity[1];
        auditId[0] = new Identity(id);
        setAudit(auditId);
        setSender(sndr);
        setService(SERVICE);
        setTrackingId(d.getTrackingId());
        serviceRef = d.getService();
    }
    
    /** Construct acknowledgment message.
     * 
     * @throws ITKException if construction fails.
     */
    public void makeMessage()
            throws ITKException
    {
        InputStream is = getClass().getResourceAsStream(ACK_TEMPLATE);
        StringBuilder sb = initContent(is);
        setDistributionEnvelope(sb.toString());
    }
    
    /** This method constructs the distribution envelope and such content from
     * the generic infrastructure ack as is common to both acks and nacks. It
     * returns a StringBuilder to that the nack subclass can perform its own
     * substitutions.
     * 
     * @param is an InputStream carrying the infrastructure ack or nack, typically
     * read from the jarfile
     * @return a StringBuilder containing the substituted template.
     * @throws ITKException 
     */
    protected StringBuilder initContent(InputStream is) 
            throws ITKException
    {
        BufferedReader br = new BufferedReader(new InputStreamReader(is));
        StringBuilder sb = new StringBuilder();
        String line = null;
        try {
            while((line = br.readLine()) != null) {
                sb.append(line);
                sb.append("\r\n");
            }
        }
        catch(Exception e) {
            throw new ITKException("SYST-0001", "Failed to read ACK template", "Internal router error");
        }
        substitute(sb, "__TRACKING_ID__", 
                UUID.randomUUID().toString().toUpperCase());
        substitute(sb, "__PAYLOAD_ID__",
                UUID.randomUUID().toString().toUpperCase());
        substitute(sb, "__SERVICE_REF__", serviceRef);
        substitute(sb, "__TIMESTAMP__", TIMESTAMP.format(new Date()));
        substitute(sb, "__SERVICE__", getService());
        substitute(sb, "__TRACKING_ID_REF__", getTrackingId());
        substitute(sb, "__AUDIT_ID__", identities.get(0).getUri());
        String to_oid = recipients.get(0).getOID();
        if (to_oid.contentEquals("2.16.840.1.113883.2.1.3.2.4.18.22")) {
            substitute(sb, "__TO_OID__", "");
        } else {
            substitute(sb, "__TO_OID__", " type=\"__EXPLICIT_OID__\" ");
            substitute(sb, "__EXPLICIT_OID__", to_oid);
        }
        substitute(sb, "__TO_URI__", recipients.get(0).getUri());
        substitute(sb, "__SENDER__", sender.getUri());
        return sb;
    }
    
    /** Perform template substitution.
     * 
     * @param sb working StringBuilder
     * @param tag substitution tag, to be replaced by...
     * @param val ... substitution value
     */
    protected void substitute(StringBuilder sb, String tag, String val) {
        int tagLength = tag.length();
        int tStart = -1;
        while ((tStart = sb.indexOf(tag)) != -1) {
            sb.replace(tStart, tStart + tagLength, val);
        }
    }
}
