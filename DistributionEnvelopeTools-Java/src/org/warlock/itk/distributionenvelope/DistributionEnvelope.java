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
/** Class to carry a distribution envelope through the router. It is made by the
 * DistributionEnvelopeHelper which extracts details needed for routing and
 * logging (addresses, sender identity and address, service and tracking id).
 *
 * @author Damian Murphy <murff@warlock.org>
 */
import java.io.StringWriter;
import java.io.Writer;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.UUID;


public class DistributionEnvelope 
    implements java.io.Serializable
{
    
    public static final String INTERACTIONID = "urn:nhs-itk:ns:201005:interaction";
    protected String envelope = null;
    protected String service = null;
    protected String trackingId = null;
    protected String interactionId = null;
    protected Address sender = null;
    protected HashMap<String,String> handlingSpecification = null;
    
    protected ArrayList<Payload> payloads = null;
    protected ArrayList<Address> recipients = null;
    protected ArrayList<Identity> identities = null;
    
    protected String itkNamespacePrefix = "itk";
    
    
    /**
     * Called by the DistributionEnvelopeHelper and the static newInstance()
     * method.
    */     
    public DistributionEnvelope() 
    {
        recipients = new ArrayList<Address>();
        identities = new ArrayList<Identity>();
    }

    /**
     * Convenience method for creating and doing basic initialisation on a
     * DistributionEnvelope instance, for use by senders.
     */    
    public static DistributionEnvelope newInstance() {
        DistributionEnvelope d = new DistributionEnvelope();
        d.setTrackingId(UUID.randomUUID().toString().toUpperCase());
        return d;
    }
            
    /**
     * When the DistributionEnvelope is serialised, by default it will use the
     * prefix "itk" for those nodes in the ITK namespace. If a sender has a
     * need for some other prefix to be used, it should be set here.
     * 
     * @param p The prefix to be used.
     */     
    public void setITKNamespacePrefix(String p) 
    {
        if ((p != null) && (p.trim().length() != 0)) {
            itkNamespacePrefix = p; 
        }
    }
    
    /**
     * Called by the DistributionEnvelopeHelper to set the recipients list
     * after it has been parsed out of the received DistributionEnvelope
     * XML.
     * 
     * @param t[] Address instances.
     */     
    protected void setTo(Address[] t) { 
        recipients.addAll(Arrays.asList(t));
    }
    
    /**
     * Called by the DistributionEnvelopeHelper to set the audit identity list
     * after it has been parsed out of the received DistributionEnvelope
     * XML.
     * 
     * @param t[] Audit Identity instances.
     */     
    protected void setAudit(Identity[] id) { 
        identities.addAll(Arrays.asList(id)); 
    }
    
    /**
     * Called by the DistributionEnvelopeHelper to set the sender address
     * after it has been parsed out of the received DistributionEnvelope
     * XML.
     * 
     * @param t Sender Address.
     */     
    protected void setSender(Address a) { sender = a; }
    
    /**
     * Called by the DistributionEnvelopeHelper to set the text of the
     * received DistributionEnvelope XML after other data have been parsed 
     * out.
     * 
     * @param d DistributionEnvelope XML as a string
     */     
    void setDistributionEnvelope(String d) { envelope = d; }
    
    /**
     * Called by the DistributionEnvelopeHelper to set the tracking id
     * of a received DistributionEnvelope.
     */    
    protected void setTrackingId(String t) { trackingId = t; }
    
    /**
     * Called by the DistributionEnvelopeHelper to set the service
     * of a received DistributionEnvelope, or by a builder to set
     * the service attribute.
     */            
    public void setService(String s) { service = s; }
    
    /**
     * Adds a handling specification given the type and value. This does
     * not validate that the given type is defined in the ITK specifications.
     * Sets the "interactionId" if the supplied type is the identifier
     * for an ITK interactionId.
     */     
    public void addHandlingSpecification(String s, String v) {
        if (handlingSpecification == null) {
            handlingSpecification = new HashMap<String,String>();
        }
        handlingSpecification.put(s, v);
        if (s.contentEquals(INTERACTIONID)) {
            interactionId = v;
        }
    }
    
    /**
     * @returns The XML text of the DistributionEnvelope.
     */     
    public String getEnvelope() { return envelope; }
    
    /**
     * @returns the serviceId 
     */    
    public String getService() { return service; }
    
    /**
     * @returns the trackingId
     */     
    public String getTrackingId() { return trackingId; }
    
    /**
     * @returns the interactionId (note that this MAY be null, and it is not
     * an error for a DistributionEnvelope to have no interactionId, so 
     * applications which require interactionId are responsible for checking
     * for null returns from this method.
     */     
    public String getInteractionId() { return interactionId; }
 
    /**
     * @returns Array of recipient Address objects, may be empty or null.
     */     
    public Address[] getTo() { 
        Address[] a = new Address[recipients.size()];
        return recipients.toArray(a); 
    }
    
    /**
     * @returns Array of author audit Identity objects. May be empty or null.
     */     
    public Identity[] getAudit() { 
        Identity[] audit = new Identity[identities.size()];
        return identities.toArray(audit); 
    }
    
    /**
     * @returns Sender Address object. May be null.
     */    
    public Address getSender() { return sender; }
    
    /**
     * Used by senders to add recipient addresses. Any address type may
     * be entered, described by the appropriate OID. Where the OID is
     * null, the default "ITK address" is supplied.
     * 
     * @param oid OID for the address type, or null
     * @param id Address 
     */     
    public void addRecipient(String oid, String id) 
            throws Exception
    {
        Address a = null;
        if (oid == null) {
            a = new Address(id);
        } else {
            a = new Address(id, oid);
        }
        recipients.add(a);
    }

    /**
    * Used by senders to add sender identities. Any identity type may
    * be entered, described by the appropriate OID. Where the OID is
    * null, the default "ITK identity" is supplied.
    * 
    * @param oid OID for the identity type, or null
    * @param id Address 
    */        
    public void addIdentity(String oid, String id)
            throws Exception
    {
        Identity ident = null;
        if (oid == null) {
            ident = new Identity(id);
        } else {
            ident = new Identity(id, oid);
        }
        identities.add(ident);
    }
    
    /**
     * (This should probably be called setSender()) Used by the
     * sender to set the sender address. Any address type may
     * be entered, described by the appropriate OID. Where the OID is
     * null, the default "ITK address" is supplied.
     * 
     * @param oid OID for the address type, or null
     * @param id Address 
     */    
    public void addSender(String oid, String id) 
            throws Exception
    {
        Address a = null;
        if (oid == null) {
            a = new Address(id);
        } else {
            a = new Address(id, oid);
        }
        sender = a;
    }
    
    /**
     * Called by the sender to set the ITK interaction id. This
     * sets the appropriate handlingSpecification. The supplied
     * value is NOT validated against any list of known, defined
     * ITK interaction ids.
     * 
     * @param id Interaction id.
     */     
    public void setInteractionId(String id) {
        addHandlingSpecification(INTERACTIONID, id);
    }
    
    /**
     *  Adds a pre-build Payload instance.
     */     
    public void addPayload(Payload p) {
        if (payloads == null){
            payloads = new ArrayList<Payload>();
        }
        payloads.add(p);
    }
    
    /**
     * When the DistributionEnvelopeHelper is used to construct a DistributionEnvelope
     * from a received message, it does not parse the payloads themselves. So the
     * DistributionEnvelope instance contains no Payload objects. If these are required,
     * the parsePayloads() method is called to parse out the payloads from the received
     * XML.
     */     
    public void parsePayloads()
            throws Exception
    {
        DistributionEnvelopeHelper helper = DistributionEnvelopeHelper.getInstance();
        Payload[] plds = helper.getPayloads(this);
        for (Payload p : plds) {
            addPayload(p);
        }
    }
    
    public void setHandlingSpecification(String key, String value) {
        addHandlingSpecification(key, value);
    }
    
//    public void setInteraction(String intId) {
//        addHandlingSpecification("urn:nhs-itk:ns:201005:interaction", intId);
//    }

    /**
     * Convenience method called by a sender to explicitly set the "ack requested" handling
     * specification.
     */         
    public void setAckRequested(boolean b) {
        addHandlingSpecification("urn:nhs-itk:ns:201005:ackrequested", Boolean.toString(b));
    }
    
    /**
     * @param key URI of the requested handling specification
     * @returns Value, or null if that handling specification is not set.
     */     
    public String getHandlingSpecification(String key) {
        if (handlingSpecification == null) {
            return null;
        }
        return handlingSpecification.get(key);
    }

    /**
     * Serialise to XML on the given Writer. 
     */    
    public void write(Writer w)
            throws Exception
    {
        if (service == null) {
            throw new Exception("No service");
        }
        if ((payloads == null) || (payloads.isEmpty())) {
            throw new Exception("No payloads");
        }
        w.write("<");
        w.write(itkNamespacePrefix);
        w.write(":DistributionEnvelope xmlns:");
        w.write(itkNamespacePrefix);
        w.write("=\"urn:nhs-itk:ns:201005\"><");
        w.write(itkNamespacePrefix);
        w.write(":header service=\"");
        w.write(service); 
        w.write("\" trackingid=\"");
        w.write(trackingId);
        w.write("\">");
        if (!recipients.isEmpty()) {
            w.write("<");
            w.write(itkNamespacePrefix);
            w.write(":addresslist>");
            for (Address a : recipients) {
                w.write("<");
                w.write(itkNamespacePrefix);
                w.write(":address");
                if (a.getOID() != null) {
                    w.write(" type=\"");
                    w.write(a.getOID());
                    w.write("\"");
                }
                w.write(" uri=\"");
                w.write(a.getUri());
                w.write("\"/>");
            }
            w.write("</");
            w.write(itkNamespacePrefix);
            w.write(":addresslist>");
        }
        if (!identities.isEmpty()) {
            w.write("<");
            w.write(itkNamespacePrefix);
            w.write(":auditIdentity>");
            for (Identity a : identities) {
                w.write("<");
                w.write(itkNamespacePrefix);
                w.write(":id");
                if (a.getOID() != null) {
                    w.write(" type=\"");
                    w.write(a.getOID());
                    w.write("\"");
                }
                w.write(" uri=\"");
                w.write(a.getUri());
                w.write("\"/>");
            }
            w.write("</");
            w.write(itkNamespacePrefix);
            w.write(":auditIdentity>");            
        }
       w.write("<");
       w.write(itkNamespacePrefix);
       w.write(":manifest count=\"");
       w.write(Integer.toString(payloads.size()));
       w.write("\">");
       for (Payload p : payloads) {
           w.write(p.makeManifestItem(itkNamespacePrefix));
       }
       w.write("</");
       w.write(itkNamespacePrefix);
       w.write(":manifest>");
       if (sender != null) {
            w.write("<");
            w.write(itkNamespacePrefix);
            w.write(":senderAddress");
            if (sender.getOID() != null) {
                w.write(" type=\"");
                w.write(sender.getOID());
                w.write("\"");
            }
            w.write(" uri=\"");
            w.write(sender.getUri());
            w.write("\"/>");          
       }
       if ((handlingSpecification != null) && !handlingSpecification.isEmpty()){
            w.write("<");
            w.write(itkNamespacePrefix);
            w.write(":handlingSpecification>");
            for (String k : handlingSpecification.keySet()) {
                w.write("<");
                w.write(itkNamespacePrefix);
                w.write(":spec key=\"");
                w.write(k);
                w.write("\" value=\"");
                w.write(handlingSpecification.get(k));
                w.write("\"/>");
            }
            w.write("</");
            w.write(itkNamespacePrefix);
            w.write(":handlingSpecification>");
       }
       w.write("</");
       w.write(itkNamespacePrefix);
       w.write(":header><");
       w.write(itkNamespacePrefix);
       w.write(":payloads count=\"");
       w.write(Integer.toString(payloads.size()));
       w.write("\">");
       for (Payload p : payloads) {
           w.write("<");
           w.write(itkNamespacePrefix);
           w.write(":payload id=\"");
           w.write(p.getManifestId());
           w.write("\">");
           w.write(p.getPayloadBody());
           w.write("</");
           w.write(itkNamespacePrefix);
           w.write(":payload>");
       }
       w.write("</");
       w.write(itkNamespacePrefix);
       w.write(":payloads></");
       w.write(itkNamespacePrefix);
       w.write(":DistributionEnvelope>");
    }
    
    /**
     * Calls write() and returns the serialised XML as a string.
     */    
    @Override
    public String toString() 
    {
        StringWriter sw = new StringWriter();
        try {
            write(sw);
        }
        catch (Exception e) {
            System.err.println("Exception serialising DistributionEnvelope: " + e.toString());
        }
        return sw.toString();
    }
    
    public boolean isAckable() {
        // Future: Need to be configured for ackable services from the
        // properties. For now, just say we don't ack InfAck/InfNack and ignore
        // that we don't ack "broadcast" either
        //
        if (service.contentEquals(AckDistributionEnvelope.SERVICE)) {
            return false;
        }
        if (service.contains("Broadcast")) {
            return false;
        }
        return true;
    }
    
    public String getPayloadId(int i)
            throws Exception
    {
        return payloads.get(i).getManifestId();
    }
}
