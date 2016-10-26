// -----BEGIN DISCLAIMER-----
/*******************************************************************************
 * Copyright (c) 2010 JCrypTool team and contributors
 *
 * All rights reserved. This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *******************************************************************************/
// -----END DISCLAIMER-----
package org.jcryptool.crypto.modern.sha3.ui;

import org.eclipse.jface.wizard.Wizard;

/**
 * Class for the wizard
 *
 * @author Michael Starzer
 *
 */
public class SHA3Wizard extends Wizard {
    private SHA3WizardPage page;

    public SHA3Wizard() {
        setWindowTitle(Messages.WizardTitle2);
    }

    public void addPages() {
        page = new SHA3WizardPage();
        addPage(page);
    }    
    
    public void setEchoText(String hashDisplay){
    	page.setEchoText(hashDisplay);
    }

    public void setJHText(String hashDisplay){
    	page.setJHText(hashDisplay);
    }
    
    public void setSkeinText(String hashDisplay){
    	page.setSkeinText(hashDisplay);
    }
    
    public boolean performFinish() {
        return true;
    }

    public String getEchoSelect() {
        return page.getEchoSelect();
    }
    public String getJHSelect() {
        return page.getJHSelect();
    }
    public String getSkeinSelect() {
        return page.getSkeinSelect();
    }

    public int getBitlength() {
        return page.getBitLength();
    }

    public String getMode() {
        return page.getMode();
    }

    public String getHashValue() {
        return page.getHashValue();
    }
    
    public String getSalt() {
        return page.getSalt();
    }
    
    public String getInputText(){
    	return page.getInputText();
    }
}
