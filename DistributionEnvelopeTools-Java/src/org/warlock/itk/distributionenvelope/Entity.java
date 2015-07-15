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
import java.util.ArrayList;
/** Common abstract superclass for Address and Identity classes. An "entity"
 * is locatable and in principle routable. It has a type, an OID associated 
 * with that type, and a URI which is the entity identifier itself, and which'
 * structure is determined by the type.
 *
 * @author Damian Murphy <murff@warlock.org>
 */
public abstract class Entity {
    
    /** Split an ITK style address into hierarchical parts.
     * 
     * @return ArrayList containing delimited hierarchichal parts of the entity identifier. 
     */
    public abstract ArrayList<String> getParts();
    
    protected static final int UNDEFINED_TYPE = -1;
    protected String uri = null;
    protected String stype = null;
    protected String oid = null;
    protected int type = UNDEFINED_TYPE;
    protected boolean isRoutable = false;
    
    /**
     * Default implementation of a URI splitter working on
     * colons as part delimiters.
     */     
    protected ArrayList<String> splitUri(String s) {
        String[] p = s.split(":");
        ArrayList<String> a = new ArrayList<String>();
        a.addAll(java.util.Arrays.asList(p));
        return a;        
    }
    
    public String getUri() { return uri; }
    public String getOID() { return oid; }
    public String getDisplayType() { return stype; }
    public int  getType() { return type; }
    public boolean isRoutable() { return isRoutable; }
}
