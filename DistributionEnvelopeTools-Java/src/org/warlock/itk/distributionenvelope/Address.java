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
/** Class representing an address in a distribution envelope.
 *
 * @author Damian Murphy <murff@warlock.org>
 */
public class Address 
    extends Entity
{
    public static final int ITK_ADDRESS = 1000;
    public static final String ITK_ADDRESS_PREFIX = "urn:nhs-uk:addressing:"; 
    public static final int ADDRESS_PREFIX_LENGTH = ITK_ADDRESS_PREFIX.length();
    
    // Some known OIDs. Right now there are only three of these supported:
    // ITK, DTS and Spine ASID. So they're given here. For extensibility 
    // they should be read from somewhere - probably a tab-delimited file
    // shipped in the JAR would be flexible enough... 
    
    private static final int[] TYPES = {1000, 1001, 1002};
    private static final String[] DISPLAYTYPES = {"ITK address (explicit)", "DTS mailbox", "Spine ASID"};
    private static final String[] OIDS = {"2.16.840.1.113883.2.1.3.2.4.18.22",
                                            "2.16.840.1.113883.2.1.3.2.4.21.1",
                                            "1.2.826.0.1285.0.2.0.107"};
    
    /** Construct an address with an implicit ITK-style address and OID.
     * 
     * @param u ITK address
     * @throws ITKException 
     */
    public Address(String u) 
            throws ITKException
    {
        if ((u == null) || (u.trim().length() == 0)) {
            throw new ITKException("ADDR-0001", "Invalid address: null or empty", null);
        }
        type = ITK_ADDRESS;
        stype = "ITK address (implicit)";
        uri = u;
        oid = OIDS[0];
        isRoutable = true;
    }
    
    /** Construct an address with an explicit type.
     * 
     * @param u Address
     * @param o OID
     * @throws ITKException 
     */
    public Address(String u, String o) 
            throws ITKException
    {
        if ((o == null) || (o.trim().length() == 0)) {
            throw new ITKException("ADDR-0002","Error in address: null or empty OID for address: " + u, null);
        }
        if ((u == null) || (u.trim().length() == 0)) {
            throw new ITKException("ADDR-0001", "Invalid address: null or empty", null);
        }
        int i = -1;
        oid = o;
        for (i = 0; i < OIDS.length; i++) {
            if (OIDS[i].contentEquals(o)) {
                type = i;
                stype = DISPLAYTYPES[i];
                uri = u;
                isRoutable = true;
                return;
            }
        }
        throw new ITKException("ADDR-0005","Unrecognised OID", o + " for address: " + u);
    }
    
    @Override
    public ArrayList<String> getParts() {
        String s = uri.substring(ADDRESS_PREFIX_LENGTH);
        return splitUri(s);
    }
}
