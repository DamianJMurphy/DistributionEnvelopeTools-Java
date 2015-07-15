/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.warlock.util.xsltransform;

import javax.xml.transform.ErrorListener;
import javax.xml.transform.TransformerException;
import org.warlock.util.Logger;
 
/**
 *
 * @author Richard Dobson <richarddobson@nhs.net>
 * 
 * This transform error listener is used to prevent the CDA template
 * transform reporting to standard error ambiguous match errors which don't break the output 
 * that the template schema is actually applied to. The redirected errors are sent to the TKW log files.
 * It is a TEMPORARY MEASURE pending the output of ongoing C&M work on improving the CDA template
 * process, and its transforms.
 **/

public class TransformErrorListenerImpl implements ErrorListener {  
public TransformerException e = null;
  
@Override
public void error(TransformerException exception) {
this.e = exception;
Logger.getInstance().log("Transform exceptions - TEMPORARY REDIRECTION: ", e.toString());
}
@Override
public void fatalError(TransformerException exception) {
this.e = exception;
Logger.getInstance().log("Transform exceptions - TEMPORARY REDIRECTION: ", e.toString());
}
@Override
public void warning(TransformerException exception) {
this.e = exception;
Logger.getInstance().log("Transform exceptions - TEMPORARY REDIRECTION: ", e.toString());
}
}
