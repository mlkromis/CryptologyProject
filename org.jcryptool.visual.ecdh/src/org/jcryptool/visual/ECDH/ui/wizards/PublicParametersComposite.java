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

import java.util.ArrayList;
import java.util.Random;

import org.eclipse.swt.SWT;
import org.eclipse.swt.custom.StackLayout;
import org.eclipse.swt.custom.StyledText;
import org.eclipse.swt.events.FocusAdapter;
import org.eclipse.swt.events.FocusEvent;
import org.eclipse.swt.events.KeyAdapter;
import org.eclipse.swt.events.KeyEvent;
import org.eclipse.swt.events.ModifyEvent;
import org.eclipse.swt.events.ModifyListener;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.events.SelectionListener;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Combo;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Group;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Spinner;
import org.eclipse.swt.widgets.Text;
import org.jcryptool.core.logging.utils.LogUtil;
import org.jcryptool.visual.ECDH.ECDHPlugin;
import org.jcryptool.visual.ECDH.Messages;
import org.jcryptool.visual.ECDH.algorithm.EC;
import org.jcryptool.visual.ECDH.algorithm.ECFm;
import org.jcryptool.visual.ECDH.algorithm.ECFp;
import org.jcryptool.visual.ECDH.algorithm.ECPoint;
import org.jcryptool.visual.ECDH.algorithm.LargeCurves;
import org.jcryptool.visual.ECDH.data.Curves;

import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.ellipticcurves.EllipticCurve;
import de.flexiprovider.common.math.ellipticcurves.EllipticCurveGF2n;
import de.flexiprovider.common.math.ellipticcurves.EllipticCurveGFP;
import de.flexiprovider.common.math.ellipticcurves.Point;
import de.flexiprovider.common.math.ellipticcurves.PointGF2n;
import de.flexiprovider.common.math.ellipticcurves.PointGFP;
import de.flexiprovider.common.math.finitefields.GF2nPolynomialElement;
import de.flexiprovider.common.math.finitefields.GF2nPolynomialField;
import de.flexiprovider.common.math.finitefields.GFPElement;

public class PublicParametersComposite extends Composite {

    private Group groupCurveType = null;
    private Group groupCurve = null;
    private Button rbtnFP = null;
    private Button rbtnLarge = null;
    private Group groupAttributes = null;
    private Composite contentFp;
    private Composite contentFm;
    private Composite contentLarge;
    private Text textInput;
    private Label label = null;
    private Button btnGenerateCurveFm = null;
    private Button btnGenerateCurveLarge = null;
    private EC curve; // @jve:decl-index=0:
    private String message;
    private EllipticCurve largeCurve; // @jve:decl-index=0:
    private FlexiBigInt fbiOrderG;
    private Combo cA;
    private Combo cB;
    private Combo cG;
    private Combo cCurve;
    private Combo cStandard;
    private Point pointG; // @jve:decl-index=0:
    private Text txtA;
    private Text txtB;
    private Text txtP;
    private Label lblP;
    private Spinner spnrM;
    private Combo cGenerator = null;
    private PublicParametersWizardPage page;
    private ECPoint[] points;
    private int n;
    private StackLayout groupAttributesLayout; // @jve:decl-index=0:
    
    public PublicParametersComposite(Composite parent, int style, PublicParametersWizardPage p,
            String m) {
        super(parent, style);
        page = p;
        parent.setSize(600, 600);
        message = m;
        initialize();
    }

    public PublicParametersComposite(Composite parent, int style, PublicParametersWizardPage p,
            EC c, ECPoint g) {
        super(parent, style);
        page = p;
        parent.setSize(600, 600);
        curve = c;
        initialize();
    }
    
    private void initialize() {
        message = Messages.getString("ECDHWizPP.default");
        //curve = new ECFp();
        //((ECFp) curve).updateCurve(1, 1, 23);
        createGroupCurve();
      // createGroupGenerator();
        setSize(new org.eclipse.swt.graphics.Point(606, 450));
        setLayout(new GridLayout());
    }

   /* private void initialize() {
        curve = new ECFp();
        ((ECFp) curve).updateCurve(1, 1, 23);
        createGroupCurve();
        createGroupGenerator();
        // setSize(new org.eclipse.swt.graphics.Point(606, 450));
        setLayout(new GridLayout());
    }*/

    /**
     * This method initializes groupCurveType
     *
     */
    private void createGroupCurveType() {
        GridData gridData6 = new GridData();
        gridData6.verticalAlignment = org.eclipse.swt.layout.GridData.FILL;
        gridData6.grabExcessHorizontalSpace = true;
        gridData6.grabExcessVerticalSpace = true;
        gridData6.horizontalAlignment = org.eclipse.swt.layout.GridData.FILL;
        GridData gridData5 = new GridData();
        gridData5.grabExcessHorizontalSpace = true;
        gridData5.horizontalAlignment = org.eclipse.swt.layout.GridData.FILL;
        gridData5.verticalAlignment = org.eclipse.swt.layout.GridData.FILL;
        gridData5.grabExcessVerticalSpace = true;
        GridData gridData3 = new GridData();
        gridData3.horizontalAlignment = org.eclipse.swt.layout.GridData.FILL;
        gridData3.grabExcessHorizontalSpace = true;
        gridData3.grabExcessVerticalSpace = true;
        gridData3.verticalAlignment = org.eclipse.swt.layout.GridData.FILL;
        GridLayout gridLayout1 = new GridLayout();
        gridLayout1.numColumns = 1;
        groupCurveType = new Group(groupCurve, SWT.NONE);
        //groupCurveType.setText(Messages.getString("ECDHWizPP.groupCurveType")); //$NON-NLS-1$
        groupCurveType.setLayoutData(gridData3);
        groupCurveType.setLayout(gridLayout1);
        rbtnFP = new Button(groupCurveType, SWT.RADIO);
        rbtnFP.setText("BLAKE"); //$NON-NLS-1$
        rbtnFP.setLayoutData(gridData5);
        rbtnFP.setSelection(true);
        
    }

    /**
     * This method initializes groupCurve
     *
     */
    private void createGroupCurve() {
        GridLayout gridLayout3 = new GridLayout();
        gridLayout3.numColumns = 2;
        groupCurve = new Group(this, SWT.NONE);
        groupCurve.setText(Messages.getString("ECDHWizPP.ellipticCurve")); //$NON-NLS-1$
        groupCurve.setLayout(gridLayout3);
        groupCurve.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, true));
        createGroupCurveType();
       // createGroupCurveSize();
        createGroupAttributes();
    }


    /**
     * This method initializes groupAttributes
     *
     */
    private void createGroupAttributes() {
        groupAttributes = new Group(groupCurve, SWT.NONE);
        groupAttributes.setText(Messages.getString("ECDHWizPP.groupAttributes")); //$NON-NLS-1$
        groupAttributes.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, true, 2, 1));
        groupAttributesLayout = new StackLayout();
        groupAttributes.setLayout(groupAttributesLayout);

        createContentFp();
        createContentFm();
        createContentLarge();
        groupAttributesLayout.topControl = contentFp;
    }

    private void createContentFp() {
        contentFp = new Composite(groupAttributes, SWT.NONE);
        contentFp.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, true));
        contentFp.setLayout(new GridLayout(2, false));
        GridData gridData = new GridData();
        gridData.grabExcessHorizontalSpace = true;
        gridData.horizontalAlignment = org.eclipse.swt.layout.GridData.FILL;
        gridData.verticalIndent = 4;
        gridData.minimumWidth = 20;
        GridData gridData3 = new GridData();
        gridData3.horizontalSpan = 2;
        gridData3.minimumWidth = 20;
        label = new Label(contentFp, SWT.NONE);
        label.setText(""); //$NON-NLS-1$
        textInput = new Text(contentFp, SWT.BORDER | SWT.V_SCROLL | SWT.MULTI);
        textInput.setSize(4000, 20);
        textInput.setText(Messages.getString("ECDHWizPP.default"));
        page.setPageComplete(true);
        textInput.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                textInput.setSelection(0, 0);
            }
        });
        textInput.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.stateMask == SWT.CTRL && e.keyCode == 'a') {
                    textInput.selectAll();
                }
            }
        });
        textInput.addModifyListener(new ModifyListener() {
            @Override
            public void modifyText(ModifyEvent e) {
                if (!textInput.getText().isEmpty()) {
                    hashInputValueHex = computeHash(comboHash.getText(), textInput.getText(), textHashInput);
                } else {
                    textHashInput.setText(""); //$NON-NLS-1$
                }

                if (!textInput.getText().isEmpty() && !textOutput.getText().isEmpty()) {
                    computeDifference();
                } else {
                    textDifference.setText(""); //$NON-NLS-1$
                }
            }
        });
    }

    private void createContentFm() {
        contentFm = new Composite(groupAttributes, SWT.NONE);
        contentFm.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, true));
        contentFm.setLayout(new GridLayout(2, false));

        Label label = new Label(contentFm, SWT.NONE);
        label.setText("m ="); //$NON-NLS-1$
        spnrM = new Spinner(contentFm, SWT.NONE);
        spnrM.setMaximum(6);
        spnrM.setSelection(4);
        spnrM.setMinimum(3);
        spnrM.setLayoutData(new GridData(SWT.FILL, SWT.BEGINNING, true, false));
        spnrM.addSelectionListener(new SelectionListener() {
            public void widgetDefaultSelected(SelectionEvent e) {
                widgetSelected(e);
            }

            public void widgetSelected(SelectionEvent e) {
                cG.removeAll();
                cA.removeAll();
                cB.removeAll();

                ((ECFm) curve).setM(spnrM.getSelection());
                int[] ia = ((ECFm) curve).getIrreduciblePolinomials();
                String[] s = new String[ia.length];
                for (int i = 0; i < s.length; i++)
                    s[i] = intToBitString(ia[i]);
                cG.setItems(s);
            }
        });
        label = new Label(contentFm, SWT.NONE);
        label.setText("f(x) ="); //$NON-NLS-1$
        cG = new Combo(contentFm, SWT.NONE);
        cG.setLayoutData(new GridData(SWT.FILL, SWT.BEGINNING, true, false));
        label = new Label(contentFm, SWT.NONE);
        label.setText("a ="); //$NON-NLS-1$
        cA = new Combo(contentFm, SWT.NONE);
        cA.setLayoutData(new GridData(SWT.FILL, SWT.BEGINNING, true, false));
     
        label = new Label(contentFm, SWT.NONE);
        label.setText("b ="); //$NON-NLS-1$
        cB = new Combo(contentFm, SWT.NONE);
        cB.setLayoutData(new GridData(SWT.FILL, SWT.BEGINNING, true, false));
        
        GridData gridData3 = new GridData();
        gridData3.horizontalSpan = 2;
        btnGenerateCurveFm = new Button(contentFm, SWT.NONE);
        btnGenerateCurveFm.setText(Messages.getString("ECDHWizPP.btnGenerateCurve")); //$NON-NLS-1$
        btnGenerateCurveFm.setLayoutData(gridData3);
        btnGenerateCurveFm.addSelectionListener(new SelectionListener() {
            public void widgetDefaultSelected(SelectionEvent e) {
                widgetSelected(e);
            }

            public void widgetSelected(SelectionEvent e) {
                Random r = new Random();
                int m = r.nextInt(3); // Set m
                while (m == 1) {
                    m = r.nextInt(3);
                }
                m += 3;
                spnrM.setSelection(m);
                ((ECFm) curve).setM(m);
                int[] ip = ((ECFm) curve).getIrreduciblePolinomials();
                String[] s = new String[ip.length];
                for (int i = 0; i < s.length; i++)
                    s[i] = intToBitString(ip[i]);
                cG.setItems(s);
                if (ip.length == 1)
                    cG.select(0);
                else
                    cG.select(r.nextInt(ip.length));
                ((ECFm) curve).setG(cG.getSelectionIndex(), true); // set G

                if (m == 3) {
                    int a = r.nextInt(3);
                    if (a == 0)
                        cA.select(3);
                    else if (a == 1)
                        cA.select(5);
                    else
                        cA.select(6);
                    ((ECFm) curve).setA(cA.getSelectionIndex(), true);
                    cB.select(0);
                    ((ECFm) curve).setB(cB.getSelectionIndex(), true);
                } else {
                    cA.select(r.nextInt(cA.getItemCount()));
                    ((ECFm) curve).setA(cA.getSelectionIndex(), true);
                    int b = r.nextInt(cB.getItemCount());
                    int count = 0;
                    do {
                        cB.select(b);
                        ((ECFm) curve).setB(cB.getSelectionIndex(), true);
                        b = (b + 1) % cB.getItemCount();
                        count++;
                    } while (cGenerator.getItemCount() == 0 && count < cB.getItemCount());

                    if (count >= cB.getItemCount()) {
                        try {
                            throw new Exception("Generator fault, could not find correct curve"); //$NON-NLS-1$
                        } catch (Exception ex) {
                            LogUtil.logError(ECDHPlugin.PLUGIN_ID, ex);
                        }
                    }
                }
            }
        });
    }

    private void createContentLarge() {
        contentLarge = new Composite(groupAttributes, SWT.NONE);
        contentLarge.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, true));
        contentLarge.setLayout(new GridLayout(4, false));
        cStandard = new Combo(contentLarge, SWT.NONE);
        cStandard.setLayoutData(new GridData(SWT.CENTER, SWT.BEGINNING, false, false, 2, 1));
        cStandard.addSelectionListener(new SelectionListener() {
            public void widgetDefaultSelected(SelectionEvent e) {
                widgetSelected(e);
            }

            public void widgetSelected(SelectionEvent e) {
                fillCSelection();
            }
        });
        cCurve = new Combo(contentLarge, SWT.NONE);
        cCurve.addSelectionListener(new SelectionListener() {
            public void widgetDefaultSelected(SelectionEvent e) {
                widgetSelected(e);
            }

            public void widgetSelected(SelectionEvent e) {
                setCurve();
            }
        });
        btnGenerateCurveLarge = new Button(contentLarge, SWT.NONE);
        btnGenerateCurveLarge.setText(Messages.getString("ECDHWizPP.btnGenerateCurve")); //$NON-NLS-1$
        btnGenerateCurveLarge.setLayoutData(new GridData(SWT.END, SWT.CENTER, true, false));
        btnGenerateCurveLarge.addSelectionListener(new SelectionListener() {
            public void widgetDefaultSelected(SelectionEvent e) {
                widgetSelected(e);
            }

            public void widgetSelected(SelectionEvent e) {
                Random r = new Random();
                if (rbtnFP.getSelection()) {
                    cStandard.select(r.nextInt(cStandard.getItemCount()));
                    fillCSelection();
                }
                cCurve.select(r.nextInt(cCurve.getItemCount()));
                setCurve();
            }
        });
        if (rbtnFP.getSelection()) {
            cStandard.setItems(LargeCurves.standardFp);
            cStandard.select(0);
            cCurve.setItems(LargeCurves.getNamesFp(0));
        } else {
            cStandard.setItems(LargeCurves.standardFm);
            cStandard.select(0);
            cCurve.setItems(LargeCurves.getNamesFm(0));
        }
        cCurve.select(0);
        Label label = new Label(contentLarge, SWT.NONE);
        label.setText("a ="); //$NON-NLS-1$
        txtA = new Text(contentLarge, SWT.BORDER | SWT.READ_ONLY);
        txtA.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, false, 3, 1));
        label = new Label(contentLarge, SWT.NONE);
        label.setText("b ="); //$NON-NLS-1$
        txtB = new Text(contentLarge, SWT.BORDER | SWT.READ_ONLY);
        txtB.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, false, 3, 1));
        lblP = new Label(contentLarge, SWT.NONE);
        lblP.setText("p ="); //$NON-NLS-1$
        txtP = new Text(contentLarge, SWT.BORDER | SWT.READ_ONLY);
        txtP.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, false, 3, 1));
    }

    private String intToBitString(int i) {
        String s = ""; //$NON-NLS-1$
        int j = i;
        while (j > 1) {
            s = (j % 2) + s;
            j /= 2;
        }
        s = (j % 2) + s;
        return s;
    }


    private void fillCSelection() {
        String[] s;
        if (rbtnFP.getSelection()) {
            s = LargeCurves.standardFp;
        } else {
            s = LargeCurves.standardFm;
        }
        cStandard.setItems(s);
        cStandard.select(0);
        fillCCurve();
    }

    private void fillCCurve() {
        String[] s;
        if (rbtnFP.getSelection()) {
            s = LargeCurves.getNamesFp(cStandard.getSelectionIndex());
        } else {
            s = LargeCurves.getNamesFm(cStandard.getSelectionIndex());
        }
        cCurve.setItems(s);
        cCurve.select(0);
        setCurve();
    }

    private void setCurve() {
        if (rbtnFP.getSelection()) {
            FlexiBigInt[] fbi = LargeCurves.getCurveFp(cStandard.getSelectionIndex(), cCurve
                    .getSelectionIndex());
            largeCurve = new EllipticCurveGFP(new GFPElement(fbi[0], fbi[2]), new GFPElement(
                    fbi[1], fbi[2]), fbi[2]);
            txtA.setText(fbi[0].toString(16));
            txtB.setText(fbi[1].toString(16));
            txtP.setText(fbi[2].toString(16));
            lblP.setText("p ="); //$NON-NLS-1$
            fbiOrderG = fbi[4];
            pointG = new PointGFP(fbi[3].toByteArray(), (EllipticCurveGFP) largeCurve);
        } else {
            FlexiBigInt[] fbi = LargeCurves.getCurveFm(cStandard.getSelectionIndex(), cCurve
                    .getSelectionIndex());
            GF2nPolynomialField field = new GF2nPolynomialField(fbi[2].intValue());
            largeCurve = new EllipticCurveGF2n(new GF2nPolynomialElement(field, fbi[0]
                    .toByteArray()), new GF2nPolynomialElement(field, fbi[1].toByteArray()), fbi[2]
                    .intValue());
            txtA.setText(fbi[0].toString(16));
            txtB.setText(fbi[1].toString(16));
            txtP.setText(fbi[2].toString(16));
            lblP.setText("m ="); //$NON-NLS-1$
            fbiOrderG = fbi[4];
            pointG = new PointGF2n(fbi[3].toByteArray(), (EllipticCurveGF2n) largeCurve);
        }
        cGenerator.setItems(new String[] {"(" + pointG.getX() + ", " + pointG.getY() + ")"}); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
        cGenerator.select(0);
        page.setPageComplete(true);
    }

    public ECPoint getGenerator() {
        return points[cGenerator.getSelectionIndex()];
    }
    
    public String getMessage() {
        return message;
    }

    public EC getCurve() {
        return curve;
    }

    public int getOrder() {
        return n;
    }


    public boolean isLarge() {
        return rbtnLarge.getSelection();
    }

    public EllipticCurve getLargeCurve() {
        return largeCurve;
    }

    public Point getLargeGenerator() {
        return pointG;
    }

    public FlexiBigInt getLargeOrder() {
        return fbiOrderG;
    }

} // @jve:decl-index=0:visual-constraint="10,10"
