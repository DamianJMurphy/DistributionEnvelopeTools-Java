/*
 * Copyright 2014 Health and Social Care Information Centre
 Solution Assurance <damian.murphy@hscic.gov.uk>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License..
 */
package org.warlock.itk.distributionenvelope;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.StringTokenizer;
        
/**
 * Singleton class to handle checks on Distribution Envelopes. This can be configured
 * either from System.properties, or via use of the addCheck() method (or both). To configure
 * via System.properties, make a property:
 * 
 * <code>org.warlock.itk.distributionenvelope.checkerlist</code>
 * 
 * containing a space-delimited list of "checker names". Then for each name, create a property:
 * 
 * <code>org.warlock.itk.distributionenvelope.checker.{checker name}</code>
 * 
 * which has a value with two space-delimited parts: service name and class name. Both must be
 * fully qualified and the class name must be resolvable by the current class loader.
 * 
 * @author Damian Murphy <damian.murphy@hscic.gov.uk>
 */
public class CheckingService {
    
    /**
     * System property. List of checker names.
     */
    private static final String CHECKERS =  "org.warlock.itk.distributionenvelope.checkerlist";
    private static final String CHECKROOT = "org.warlock.itk.distributionenvelope.checker.";
    
    private static final int SERVICE = 0;
    private static final int CLASS = 1;
    
    private static CheckingService me = new CheckingService();
    
    private HashMap<String,ArrayList<DistributionEnvelopeChecker>> checks = null;
    
    private CheckingService() {
        checks = new HashMap<String,ArrayList<DistributionEnvelopeChecker>>();
        String p = System.getProperty(CHECKERS);
        if (p != null) {
            StringTokenizer st = new StringTokenizer(p);
            while (st.hasMoreElements()) {
                String checkname = st.nextToken();
                String checkProperty = System.getProperty(CHECKROOT + checkname);
                if (checkProperty == null) {
                    // TODO: Log properly
                    System.err.println("Check property " + CHECKROOT + checkname + " expected but not set");
                    continue;
                }
                String[] parts = checkProperty.split(" +");
                try {
                    addCheck(parts[SERVICE], parts[CLASS]);
                }
                catch (Exception e) {
                    // TODO: Log properly
                    System.err.println("Check property " + CHECKROOT + checkname + " initialisation failed: " + e.toString());
                }
            }
        }
    }
    
    /**
     * Add a check for the given service name, using the given class name. Both must be fully
     * qualified, and the class name must be resolvable by the current class loader. The class name
     * must be a class that can be case to org.warlock.itk.DistributionEnvelope.DistributionEnvelopeChecker
     * 
     * @param s Fully-qualified ITK service name (will be read from the Distribution Envelope to be checked)
     * @param c Class name of check.
     * @throws Exception if something goes wrong. Typically a problem loading or instantiating the check.
     */
    public final void addCheck(String s, String c)
            throws Exception
    {
        DistributionEnvelopeChecker chk = (DistributionEnvelopeChecker)Class.forName(c).newInstance();
        chk.setService(s);
        if (checks.containsKey(s)) {
            checks.get(s).add(chk);
        } else {
            ArrayList<DistributionEnvelopeChecker> a = new ArrayList<DistributionEnvelopeChecker>();
            a.add(chk);
            checks.put(s, a);
        }
    }
    
    /**
     * Singleton getInstance() method.
     * public
     * @return 
     */
    public static final CheckingService getInstance() { return me; }
    
    /**
     * 
     * @param d
     * @param o
     * @return
     * @throws Exception 
     */
    public ArrayList<String> getCheckFailures(DistributionEnvelope d, Object o)
            throws Exception
    {
        if (d == null)
            return null;
        
        ArrayList<String> failures = null;
        if (!checks.containsKey(d.getService()))
            return null;
        
        ArrayList<DistributionEnvelopeChecker> a = checks.get(d.getService());
        for (DistributionEnvelopeChecker c : a) {
            String r = c.check(d, o);
            if (r != null) {
                if (failures == null) {
                    failures = new ArrayList<String>();
                }
                failures.add(r);
            }
        }
        return failures;
    }
}
