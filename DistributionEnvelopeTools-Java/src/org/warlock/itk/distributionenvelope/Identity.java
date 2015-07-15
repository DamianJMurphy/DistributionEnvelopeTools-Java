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
import java.util.ArrayList;
import org.warlock.itk.util.ITKException;
/** Class representing an audit identity from the distribution envelope.
 *
 * @author Damian Murphy <murff@warlock.org>
 */
public class Identity 
    extends Entity
{
    public static final int ITK_IDENTITY = 10000;
    
    public static final String ITK_IDENTITY_PREFIX = "urn:nhs-uk:identity:";   
    public static final int IDENTITY_PREFIX_LENGTH = ITK_IDENTITY_PREFIX.length();
    
    
    // Some known OIDs. Right now there are only five of these supported:
    // ITK, DTS and Spine UID/URP/ORG. So they're given here. For extensibility 
    // they should be read from somewhere - probably a tab-delimited file
    // shipped in the JAR would be flexible enough... 
    
    // For an Identity, these "known OIDs" implement the routing requirement
    // that an "externally meaningful" identity be provided: if it isn't one
    // of these it is no good.
    
    private static final int[] TYPES = {10000, 10001, 10002, 10003, 10004};
    private static final String[] DISPLAYTYPES = {"ITK identity (explicit)", "DTS mailbox", "Spine UID", "Spine URP", "Spine ORG", "Spine ASID"};
    private static final String[] OIDS = {"2.16.840.1.113883.2.1.3.2.4.18.27",
                                            "2.16.840.1.113883.2.1.3.2.4.21.1",
                                            "1.2.826.0.1285.0.2.0.65",
                                            "1.2.826.0.1285.0.2.0.67",
                                            "1.2.826.0.1285.0.2.0.109",
                                            "1.2.826.0.1285.0.2.0.107"};
    
    private boolean external = false;
    
    public Identity(String u) 
            throws ITKException
    {
        if ((u == null) || (u.trim().length() == 0)) {
            throw new ITKException("ADDR-0003", "Invalid identity: null or empty", null);
        }
        type = ITK_IDENTITY;
        stype = "ITK identity (implicit)";
        uri = u;
        oid = OIDS[0];
        isRoutable = true;
    }
    
    public Identity(String u, String o) 
            throws ITKException
    {
        if ((o == null) || (o.trim().length() == 0)) {
            throw new ITKException("ADDR-0004", "Error in identity: null or empty OID for identity: " + u, null);
        }
        if ((u == null) || (u.trim().length() == 0)) {
            throw new ITKException("ADDR-0003", "Invalid identity: null or empty", null);
        }
        oid = o;
        int i = -1;
        for (i = 0; i < OIDS.length; i++) {
            if (OIDS[i].contentEquals(o)) {
                type = i;
                stype = DISPLAYTYPES[i];
                uri = u;
                external = true;
                isRoutable = (type == ITK_IDENTITY);
                return;
            }
        }
    }
    
    public boolean isExternal() { return external; }
    
    @Override
    public ArrayList<String> getParts() {
        String s = uri.substring(IDENTITY_PREFIX_LENGTH);
        return splitUri(s);    
    }
    
}
