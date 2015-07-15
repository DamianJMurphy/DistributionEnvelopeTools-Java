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
package org.warlock.itk.util;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

/** Central exception for reporting trouble in the ITK application. 
 * Handles logging and can be used for reporting to routing requestors via 
 * ITK routing infrastructure NACKs.
 *
 * @author Damian Murphy <murff@warlock.org>
 */
public class ITKException 
    extends Exception
{
    private static final SimpleDateFormat TIMESTAMP = new SimpleDateFormat("'At' yyyyMMddHHmmss' : '");

    public static final String SYSTEM_LOGGER = "ITKApplicationSystemLog";
    
    private String id = null;
    private String code = null;
    private String text = null;
    private StringBuilder diagnostics = null;
    private String applicationContext = null;
    private String messageId = null;
    private String sender = null;
    
    private Level loggingLevel = null;
    
    private boolean stackTrace = true;
    
    /** Make the exception. The three fields map to the elements of the ITK
     * XML error structure.
     * 
     * @param c Error code
     * @param t Error text
     * @param d Diagnostic text.
     */
    public ITKException(String c, String t, String d) {
        id = UUID.randomUUID().toString().toUpperCase();
        code = c;
        text = t;
        diagnostics = new StringBuilder(TIMESTAMP.format(new Date()));
        diagnostics.append((d == null) ? "No diagnostics given" : d);
    }

    /** Make the exception. The three fields map to the elements of the ITK
     * XML error structure.
     * 
     * @param c Error code
     * @param t Error text
     * @param d Diagnostic text.
     * @param e Causing exception
     */
    public ITKException(String c, String t, String d, Exception e) {
        super(e);
        id = UUID.randomUUID().toString().toUpperCase();
        code = c;
        text = t;
        diagnostics = new StringBuilder(TIMESTAMP.format(new Date()));
        diagnostics.append((d == null) ? "No diagnostics given" : d);
    }
    
    /**
     * Safely call Throwable.initCause() on this ITKException, does nothing if
     * either the given Throwable is this ITKException, or if this already
     * has its causing exception set, either through the constructor or a
     * previous call to this method.
     * 
     * @param e Causing exception
     */
    public void setCause(Throwable e) {
        if (e == this) return;
        if (getCause() == null) {
            initCause(e);
        }
    }
    
    /** Turn off stack tracing in logs, for this exception. This is used for
     * "non error" conditions such as "blocking" routes, where there is a need
     * to nack the message, but where no actual error has occurred and the 
     * ITKException hasn't actually been thrown, so a stack
     * trace is inappropriate.
     * 
     */
    public void noStackTrace() { stackTrace = false; }
    
    /** Add context information and log the error. Any can be null.
     * 
     * @param n Application context
     * @param m Tracking id
     * @param s Sender 
     */
    public void recordContext(String n, String m, String s) { 
        applicationContext = n; 
        messageId = m;
        sender = s;
        log();
    }

    /**
     * Set the logging level for reporting this ITKException, if the default
     * java.util.logging.Level.WARNING is not what is wanted. Note that this
     * does NOT filter java.util.logging.Level.OFF so it assumes the caller 
     * knows what they are doing.
     * 
     * @param l Level to set logging
     */
    public void setLoggingLevel(Level l) { loggingLevel = l; }
    
    /** Add context information and log the error. Any can be null.
     * 
     * @param s Sender 
     */    
    public void report(String s) {
        sender = s;
        log();
    }
    
    /** Make a detailed error report for logging.
     * 
     * @return Error report 
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        
        sb.append("ITKException\n");
        sb.append("ID:\t");
        sb.append(id);
        sb.append("\nCode:\t");
        sb.append(code);
        sb.append("\nText:\t");
        sb.append(text);
        sb.append("\nDiagnostics:\n");
        sb.append(diagnostics.toString());
        if (applicationContext == null) {
            sb.append("\nApplicationContext: Not set");
        } else {
            sb.append("\nApplicationContext: ");
            sb.append(applicationContext);
        }
        if (messageId == null) {
            sb.append("\nTransmission id: Not set");
        } else {
            sb.append("\nTransmission id: ");
            sb.append(messageId);
        }
        if (sender == null) {
            sb.append("\nSender: Not set");
        } else {
            sb.append("\nSender: ");
            sb.append(sender);
        }
        if (stackTrace) {
            fillInStackTrace();
            sb.append("\n\nStack Trace:\n");
            for (StackTraceElement ste : this.getStackTrace()) {
                sb.append("\nat ");
                sb.append(ste.getClassName());
                sb.append(".");
                sb.append(ste.getMethodName());
                sb.append("(");
                sb.append(ste.getFileName());
                sb.append(":");
                sb.append(ste.getLineNumber());
                sb.append(")");
            }
        }
        return sb.toString();
    }
    
    public String getId() { return id; }
    public String getCode() { return code; }
    public String getText() { return text; }
    public String getDiagnostics() { return diagnostics.toString(); }
    
    /** Append a comma, then some text, to the diagnostics.
     * 
     * @param s text to append 
     */
    public void updateDiagnostics(String s) {
        diagnostics.append(", ");
        diagnostics.append(s);
    }
    
    private void log() {
        String lname = (applicationContext == null) ? SYSTEM_LOGGER : applicationContext;
        Logger l = Logger.getLogger(lname);
        Level lvl = (loggingLevel == null) ? Level.WARNING : loggingLevel;        
        l.log(lvl, this.toString());
    }
}
