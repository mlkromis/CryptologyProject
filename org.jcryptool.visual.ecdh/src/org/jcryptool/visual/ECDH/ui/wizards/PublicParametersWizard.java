// -----BEGIN DISCLAIMER-----
/*******************************************************************************
 * Copyright (c) 2011 JCrypTool Team and Contributors
 *
 * All rights reserved. This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *******************************************************************************/
// -----END DISCLAIMER-----
package org.jcryptool.visual.ECDH.ui.wizards;

import org.eclipse.jface.wizard.Wizard;
import org.jcryptool.visual.ECDH.algorithm.EC;
import org.jcryptool.visual.ECDH.algorithm.ECPoint;

import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.ellipticcurves.EllipticCurve;
import de.flexiprovider.common.math.ellipticcurves.Point;

import org.jcryptool.visual.ECDH.algorithm.BLAKEAction;
import org.jcryptool.visual.ECDH.algorithm.BLAKEAlgorithm;
import org.jcryptool.visual.ECDH.algorithm.BLAKEHashState;

public class PublicParametersWizard extends Wizard {
    private PublicParametersWizardPage page;
    private ECPoint generator;
    private EC curve;
    private int order;
    private boolean large;
    private EllipticCurve largeCurve;
    private Point pointG;
    private FlexiBigInt largeOrder;
    private String message;

    public PublicParametersWizard(String m) {
        super();
        message = m;
        setNeedsProgressMonitor(true);
    }
    
    public PublicParametersWizard(EC c, ECPoint g) {
        super();
        curve = c;
        generator = g;
        setNeedsProgressMonitor(true);
    }

    @Override
    public void addPages() {
        page = new PublicParametersWizardPage(message);
        addPage(page);
    }

    @Override
    public boolean performFinish() {
       
        message = page.getMessage();
        return true;
    }

    public String getMessage() {
        return message;
    }
    
    public ECPoint getGenerator() {
        return generator;
    }

    public EC getCurve() {
        return curve;
    }

    public int getOrder() {
        return order;
    }

    public boolean isLarge() {
        return large;
    }

    public EllipticCurve getLargeCurve() {
        return largeCurve;
    }

    public Point getLargeGenerator() {
        return pointG;
    }

    public FlexiBigInt getLargeOrder() {
        return largeOrder;
    }
}