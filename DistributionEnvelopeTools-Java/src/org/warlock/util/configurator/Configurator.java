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
package org.warlock.util.configurator;
import java.util.Map;
import java.util.List;
/** Abstract superclass for a Configurator. This exists to allow platform- or
 * container-specific configuration systems to be used to supply properties.
 * The default implementation is based on System.properties - which is less
 * efficient than just using System.properties if you know that is all you 
 * are ever going to use. The Configurator mechanism allows other types of
 * configuration source to be built. It also contains a notifier so that 
 * registered listeners can be informed of changes.
 *
 * @author Damian Murphy <murff@warlock.org>
 */
public abstract class Configurator {
    
    protected static Configurator me = init();
    protected static Exception bootException = null;
    
    Configurator() {}
    
    protected static Configurator init() {
        String configuratorClass = System.getProperty("org.warlock.util.configurator.class");
        if (configuratorClass == null) {
            configuratorClass = "org.warlock.util.configurator.DefaultSystemPropertiesConfigurator";
        }
        Configurator c = null;
        try {
            c = (Configurator)Class.forName(configuratorClass).newInstance();
        }
        catch (Exception e) {
            bootException = e;
        }
        return c;
    }
    
    public static Configurator getConfigurator()
            throws Exception
    {
        if (bootException != null) {
            throw bootException;
        }
        return me;
    }

    /**
     * Set the given configuration to the supplied value, add it if not present..
     * 
     * @param key
     * @param value
     * @throws Exception 
     */
    public abstract void setConfiguration(String key, String value) throws Exception;
    
    /**
     * Clear all configurations.
     * 
     * @throws Exception if the configurator is not editable.
     */
    public abstract void clear() throws Exception;
    /**
     * Remove a configuration if it is present.
     * 
     * @param key 
     */
    public abstract void removeConfiguration(String key) throws Exception;
    /** Register a listener which will be notified of configuration changes.
     * 
     * @param l Implementation of ConfigurationListener 
     */
    public abstract void registerConfigurationListener(ConfigurationListener l);
    
    /** Get a single string property
     * 
     * @param key
     * @return Single string property, or null if the key is not found. 
     */
    public abstract String getConfiguration(String key);
    
    /** Get a Map property (i.e. the key references a java.util.Map)
     * 
     * @param key
     * @return Map property, or null if the key is not found. 
     */
    public abstract Map getConfigurationMap(String key);

    /** Get a List property (i.e. the key references a java.util.List)
     * 
     * @param key
     * @return List property, or null if the key is not found. 
     */
    public abstract List getConfigurationList(String key);
}
