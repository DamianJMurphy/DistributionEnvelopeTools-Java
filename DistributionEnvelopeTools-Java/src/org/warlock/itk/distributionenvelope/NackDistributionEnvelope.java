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
import java.io.InputStream;
import org.warlock.itk.util.ITKException;
/** Class for constructing and sending a negative acknowledgment.
 *
 * @author Damian Murphy <murff@warlock.org>
 */
public class NackDistributionEnvelope 
    extends AckDistributionEnvelope
{
    private static final String NACK_TEMPLATE = "infrastructure_nack_template.xml.txt";
    private ITKException ex = null;
    
    /** Construct a negative acknowledgment, reporting the ITKException to the
     * sender of the distribution envelope.
     * 
     * @param d DistributionEnvelope to nack
     * @param e ITKException to report in the nack.
     * @throws ITKException 
     */
    public NackDistributionEnvelope(DistributionEnvelope d, ITKException e)
            throws ITKException
    {
        super(d);
        ex = e;
    }
    
    @Override
    public void makeMessage()
            throws ITKException
    {
        InputStream is = getClass().getResourceAsStream(NACK_TEMPLATE);
        StringBuilder sb = initContent(is);
        
        // Exception subsititutions (based on template)
        //
        substitute(sb, "__ERROR_ID__", ex.getId());
        substitute(sb, "__ERROR_CODE__", ex.getCode());
        substitute(sb, "__ERROR_TEXT__", ex.getText());
        if (ex.getDiagnostics() == null) {
            substitute(sb, "__ERROR_DIAGNOSTICS__", "");
        } else {
            substitute(sb, "__ERROR_DIAGNOSTICS__", "<itk:ErrorDiagnosticText><![CDATA[__ERR_DIAG_REWRITE__]]></itk:ErrorDiagnosticText>");
            substitute(sb, "__ERR_DIAG_REWRITE__", ex.getDiagnostics());
        }
        setDistributionEnvelope(sb.toString());
    }        
}
