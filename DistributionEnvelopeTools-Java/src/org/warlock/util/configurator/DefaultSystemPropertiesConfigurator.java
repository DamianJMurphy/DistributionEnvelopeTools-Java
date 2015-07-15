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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Properties;
import java.io.FileReader;
/** Simple configurator implementation based on System properties.
 *
 * @author Damian Murphy <murff@warlock.org>
 */
public class DefaultSystemPropertiesConfigurator 
    extends Configurator
{
    private Properties properties = System.getProperties();
    private ArrayList<ConfigurationListener> listeners = null;
    
    DefaultSystemPropertiesConfigurator()  {
        listeners = new ArrayList<ConfigurationListener>();
        String propertiesfile = System.getProperty("org.warlock.util.SystemPropertiesConfiguraor.filename");
        try {
            System.getProperties().load(new FileReader(propertiesfile));
        }
        catch (Exception e) {
            bootException = e;
        }
    }
    
    @Override
    public void removeConfiguration(String key) {}
    
    @Override
    public void clear() {}
    
    @Override
    public void setConfiguration(String key, String value) {}
    
    @Override
    public void registerConfigurationListener(ConfigurationListener l)
    {
        listeners.add(l);
    }
    
    @Override
    public String getConfiguration(String key)
    {
        return properties.getProperty(key);
    }
    
    /** Not supported in system properties
     * 
     * @param key
     * @return 
     */
    @Override
    public HashMap getConfigurationMap(String key)
    {
        return null;
    }
    
    /** Not supported in system properties.
     * 
     * @param key
     * @return 
     */
    @Override
    public ArrayList getConfigurationList(String key)
    {
        return null;
    }   
}
