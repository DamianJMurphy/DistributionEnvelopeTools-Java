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

import java.io.File;
import java.io.FileWriter;

/**
 * Added file locking for log files to ensure that the writing thread in the OS is fully disengaged before other threads attempt a read.
 * Requires a tks.Toolkit.logfilelocker (Y/N) to the tkw.properties to switch on/off
 * 
 * @author riro
 */
public class FileLocker {
    public void lock(String s)
            throws Exception{
        
        File f = new File(s.concat(".lck"));
        f.createNewFile();
//        System.out.println("Lock");

    }
    public void unlock(String s)
            throws Exception{
        File f = new File(s.concat(".lck"));
        f.delete();
//        System.out.println("Unlock");
    }
    public boolean hasLock(String s) 
            throws Exception{
//        System.out.println("Has Lock");
        File f = new File(s.concat(".lck"));
        if(f.exists()){
            return true;      
        }else{
            return false;            
        }
    }
}
