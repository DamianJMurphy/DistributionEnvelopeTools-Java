/*
  Copyright 2012  Damian Murphy <murff@warlock.org>

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
package org.warlock.util.xsltransform;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.Templates;
import javax.xml.transform.Transformer;
import javax.xml.transform.URIResolver;
import javax.xml.transform.stream.StreamSource;
import javax.xml.transform.stream.StreamResult;
import java.io.File;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.HashMap;
import org.warlock.util.configurator.Configurator;
 /**
 * Manager class for pre-compiling and providing access to named XSL transforms.
 * 
 * @author Damian Murphy <murff@warlock.org>
 */
public class TransformManager {

    private static final String FACTORYCLASS = "net.sf.saxon.TransformerFactoryImpl";

    private final TransformerFactory transformerFactory = TransformerFactory.newInstance();;
    private TransformErrorListenerImpl errorHandler;
    private static final TransformManager manager = new TransformManager();
    private final HashMap<String,Templates> transforms = new HashMap<>();
    private final HashMap<String,URIResolver> resolvers = new HashMap<>();

    private static Exception bootException = null;
    private TransformManager()
    {
        try {
            System.setProperty("javax.xml.transform.TransformerFactory", FACTORYCLASS);
            Configurator config = Configurator.getConfigurator();
            String redirectTransformErrors = config.getConfiguration("tks.debug.redirecttransformerrors");
            if ((redirectTransformErrors == null) || (redirectTransformErrors.toUpperCase().startsWith("Y"))) {
                errorHandler=new TransformErrorListenerImpl();
                transformerFactory.setErrorListener(errorHandler);
                }
            }
            catch (Exception e) {
                bootException = e;
            }
    }

    public static TransformManager getInstance()
        throws Exception
    {
        if (bootException != null) {
            throw new Exception("Exception occurred initialising transformer", bootException);
        }
        return manager;
    }
    
    public String doTransform(String tname, InputStream input)
            throws Exception
    {
        return doTransform(tname, new InputStreamReader(input));
    }
    
    public String doTransform(String tname, Reader input)
            throws Exception
    {
        if (!transforms.containsKey(tname)) {
            throw new Exception("Transform not found: " + tname);
        }
        StreamSource s = new StreamSource(input);
        StringWriter w = new StringWriter();
        StreamResult r = new StreamResult(w);
        Transformer t = transforms.get(tname).newTransformer();

        if (resolvers.containsKey(tname)) {
            t.setURIResolver(resolvers.get(tname));
        }

        // rido2 - debug point. Check tks.log.transform.errors for logging of transform errors. Default is to log.
//        String redirectTransformErrors = System.getProperty("tks.debug.redirecttransformerrors");
//        if ((redirectTransformErrors == null) || (redirectTransformErrors.toUpperCase().startsWith("Y"))) {
//        TransformErrorListenerImpl errorHandler=new TransformErrorListenerImpl();
        if(errorHandler!= null){
            t.setErrorListener(errorHandler);
        }
//        }
        // rido2 - end debug point.
//        synchronized(t)
//        {        
            t.transform(s, r);        
//        }
        return w.getBuffer().toString();        
    }
    
    public String doTransform(String tname, String input)
            throws Exception
    {
        if (!transforms.containsKey(tname)) {
            throw new Exception("Transform not found: " + tname);
        }
        StreamSource s = new StreamSource(new StringReader(input));
        StringWriter w = new StringWriter();
        StreamResult r = new StreamResult(w);
        Transformer t = transforms.get(tname).newTransformer();
        if (resolvers.containsKey(tname)) {
            t.setURIResolver(resolvers.get(tname));
        }
//        synchronized(t) {
            t.transform(s, r);
//        }
//        return r.toString();
        return w.getBuffer().toString();
    }

    public void addTransform(String name, InputStream is)
            throws Exception
    {
        if (transforms.containsKey(name)) {
            return;
        }
        StreamSource s = new StreamSource(is);
        Templates t = null;
        t = transformerFactory.newTemplates(s);
        Transformer tf = t.newTransformer();
        tf.reset();
        transforms.put(name, t);
    }

    public void setURIResolver(String name, URIResolver r)
            throws Exception
    {
        if (!transforms.containsKey(name)) {
            throw new Exception("No such transform");
        }
        resolvers.put(name, r);
    }

    public URIResolver getFactoryURIResolver() {
        return transformerFactory.getURIResolver();
    }
    
    public void setFactoryURIResolver(URIResolver r) {
        transformerFactory.setURIResolver(r);
    }
    
    public void addTransform(String name, String filename)
            throws Exception
    {
        if (transforms.containsKey(name)) {
            return;
        }
        File f = new File(filename);
        if (!f.exists()) {
            throw new Exception("Transform file " + f + " not found");
        }
        StreamSource s = new StreamSource(f);
        Templates t = null;
        t = transformerFactory.newTemplates(s);
        Transformer tf = t.newTransformer();
        tf.reset();
        transforms.put(name, t);
    }
}
