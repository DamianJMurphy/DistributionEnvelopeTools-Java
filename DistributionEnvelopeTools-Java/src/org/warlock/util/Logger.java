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

package org.warlock.util;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.logging.ConsoleHandler;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.SimpleFormatter;
/**
 *  A Singleton class for logging.
 *
 *  The logfile name pattern: [application name]_yyyyMMddHHmmss.log in the specified directory
 *
 *  Note:  setAppName(String name, String ldir) should be called before any loging call.  
 *         closeLog() will close the logging file.
 *         setAppName() and closeLog() should be called as a pair with a logging file.
 *
 * NOTE: This is very old code. It is planned to replace its use with the standard Java
 * logging facility.
 * 
 * @author Damian Murphy <murff@warlock.org>
 */
public class Logger {
    
    private java.util.logging.Logger appLogger = null;
    private static final SimpleDateFormat dateStringFormat = new SimpleDateFormat("yyyyMMddHHmmss");
    public static final String CONSOLE_LOGGER = "Console";

    private static String logDir = null;
    private String appName = null;
    private static String dateString = null;
    private static Logger me = null;
    private static String logFileName = null;
    private boolean useAppLogger = false;
    
    /** Creates a new instance of Logger */
    private Logger() {
        dateString = dateStringFormat.format(new Date());
        java.util.logging.Logger consoleLogger = java.util.logging.Logger.getLogger(CONSOLE_LOGGER);
        ConsoleHandler ch = new ConsoleHandler();
        ch.setFormatter(new SimpleFormatter());
        consoleLogger.addHandler(ch);
    }
        
      
    public static String getDate() { return dateStringFormat.format(new Date()); }
        
    public void log(String location, String message) {
        info(location, message);
    }
    
    public void warn(String location, String message) {
        log(Level.WARNING, location, message);
    }
    
    public void info(String location, String message) {
        log(Level.INFO, location, message);
    }
    
    public void error(String location, String message) {
        log(Level.SEVERE, location, message);
    }
    /**
     *  Log the given message, declare it as coming from the given location.
     *
     *  If the log file has not been opened successfully, the error will be sent via the standard err channel.
     *   
     * @param l java.util.logging.Level
     *  @param location  where the message has been raised.
     *  @param message   the message to be logged. 
     */
    public void log(Level l, String location, String message) {
        StringBuilder sb = new StringBuilder();        
        sb.append("Location: ");
        if ((location == null) || (location.trim().length() == 0))
            sb.append("Not given");
        else
            sb.append(location);
        sb.append(" : Message: ");
        if ((message == null) || (message.trim().length() == 0))
            sb.append("Not given");
        else
            sb.append(message);

        java.util.logging.Logger eventlog = null;
        if (useAppLogger) {
            eventlog = appLogger;
        } else {
            eventlog = java.util.logging.Logger.getLogger(CONSOLE_LOGGER);
        }
        eventlog.setUseParentHandlers(false);
        eventlog.log(l, sb.toString());
    }
    
    /**
     *  return the singleton instance of this class.
     */
    public static synchronized Logger getInstance() {
        if (me == null)
            me = new Logger();
        return me;
    }
    
    public void close() {
        if (appName != null) {
            java.util.logging.Logger log = null;
            log = java.util.logging.Logger.getLogger(appName);
            for (Handler h : log.getHandlers()) {
                h.close();
            }
        }
    }
    
    /**
     *  set the application name and logging direction for the composition of 
     *  log filename 
     *  
     *  the function will attempt to create a log file;
     *  if successful, the instance is ready for logging, 
     *  otherwise an error will be sent via the standard err channel.  
     *
     *  @param  name    application name
     *  @param  ldir    the log file directory
     */
    public void setAppName(String name, String ldir) {
        if ((name == null) || (name.trim().length() == 0))
            return;
        if ((ldir == null) || (ldir.trim().length() == 0))
            return;
        if (appName == null) {
            logDir = ldir;
            appName = name;
            
            appLogger = java.util.logging.Logger.getLogger(appName); 
            appLogger.setUseParentHandlers(false);
            StringBuilder sb = new StringBuilder(logDir);
            if(!(logDir.endsWith("/") || logDir.endsWith("\\"))) {
                sb.append("/");
            }
            sb.append(appName);
            sb.append("_");
            sb.append(dateString);
            sb.append(".log");
            logFileName = sb.toString();
            try {
                FileHandler fh = new FileHandler(logFileName, 0, 1, true);
                fh.setFormatter(new SimpleFormatter());
                appLogger.addHandler(fh);
                useAppLogger = true;
            }
            catch (Exception e) {
                java.util.logging.Logger consoleLogger = java.util.logging.Logger.getLogger(CONSOLE_LOGGER);
                StringBuilder sbe = new StringBuilder("Failed to initialise logger ");
                sbe.append(appName);
                sbe.append(" to ");
                sbe.append(logFileName);
                sbe.append(" : ");
                sbe.append(e.toString());
                consoleLogger.log(Level.SEVERE,  sbe.toString());
            }            
        }
    }

    /**
     * Logs the given string with a level of "INFO".
     * @param string Message to log
     */
    public void log(String string) {
        this.log(Level.INFO, "Location not given", string);
    }
    
}
