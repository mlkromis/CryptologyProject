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
import java.io.InputStream;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.eclipse.core.commands.ExecutionEvent;
import org.eclipse.jface.dialogs.MessageDialog;
import org.eclipse.jface.window.Window;
import org.eclipse.jface.wizard.WizardDialog;
import org.eclipse.jface.wizard.WizardPage;
import org.eclipse.osgi.util.NLS;
import org.eclipse.swt.SWT;
import org.eclipse.swt.events.VerifyEvent;
import org.eclipse.swt.events.VerifyListener;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Combo;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Event;
import org.eclipse.swt.widgets.Group;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Listener;
import org.eclipse.swt.widgets.Text;
import org.eclipse.ui.IEditorInput;
import org.eclipse.ui.PartInitException;
import org.eclipse.ui.PlatformUI;
import org.jcryptool.core.operations.IOperationsConstants;
import org.jcryptool.core.operations.editors.AbstractEditorService;
import org.jcryptool.crypto.modern.sha3.SHA3Plugin;
import org.jcryptool.crypto.modern.sha3.blake.BLAKEAction;
import org.jcryptool.crypto.modern.sha3.echo.ECHOAction;
import org.jcryptool.crypto.modern.sha3.jh.JHAction;
import org.jcryptool.crypto.modern.sha3.skein.algorithm.SkeinAction;
import org.jcryptool.crypto.modern.sha3.groestl.GroestlAction;

/**
 * Implements the sha3 wizardpage
 *
 * @author Michael Starzer
 *
 */
public class SHA3WizardPage extends WizardPage implements Listener {
	
	
	private static final int UNSIGNED_BYTE_MASK = 0xFF;
	
	
	//private Composite algorithmGroup;
    private Composite bitlengthGroup;
    //private Label algorithmListLabel;
    private Label BitlengthListLabel;
    //private Combo AlgorithmCombo;
    private Combo BitlengthCombo;
    
    private Group InputTextGroup;
    private Text InputText;
    private String InputEcho;   
    
    private Group SaltGroup;
    private Button Salt;
    private Text SaltValue;
    private String SaltEcho = "";    
    
    private Group AlgorithmGroup;
    private Text EchoName;
    private Text EchoNone;
    private Button EchoHash;
    private Text EchoOutput;
    private Button JHHash;
    private Text JHOutput;
    private Button SkeinHash;
    private Text SkeinOutput;
    private Button BlakeHash;
    private Text BlakeOutput;
    private Button KeccakHash;
    private Text KeccakOutput;
    private Button GroestlHash;
    private Text GroestlOutput;
    /**
     * Option group for choosing create or verify hash
     */
    private Group OptionGroup;
    private Button CreateHash;
    private Button VerifyHash;
    private Text HashValue;
    /**
     * The inserted hash of the user
     */
    private String Hash;

    /**
     * The chosen mode (hexeditor, texteditor, hashstream)
     */
    private int EchoSelect = 0;
    private int JHSelect = 0;
    private int SkeinSelect = 0;
    private int BlakeSelect = 0;
    private int KeccakSelect = 0;
    private int GroestlSelect = 0;
    private int Bitlength = 1;
    private boolean Mode = false;
    
    
    private Group SubmitGroup;
    private Button Submit;
    
    public SHA3WizardPage() {
        super(".", "SHA3", null);
        setTitle(Messages.WizardTitle);
        setMessage(Messages.WizardMessage0);
    }

    
    
    /**
     * Control-group for the wizard
     */
    public void createControl(Composite parent) {
        Composite pageComposite = new Composite(parent, SWT.NULL);
        createInputTextGroup(pageComposite);
        createBitlengthGroup(pageComposite);
        //AlgorithmCombo.select(0);
        BitlengthCombo.removeAll();
        BitlengthCombo.add("224");
        BitlengthCombo.add("256");
        BitlengthCombo.add("384");
        BitlengthCombo.add("512");
        BitlengthCombo.add("1024");
        BitlengthCombo.select(1);
        createOptionGroup(pageComposite);
        createSaltGroup(pageComposite);
        createAlgorithmGroup(pageComposite);
        CreateHash.setSelection(true);
        HashValue.setEnabled(false);
        pageComposite.setLayout(new GridLayout());
        createSubmitGroup(pageComposite);
        setControl(pageComposite);
        setPageComplete(mayFinish());
    	//***UNCOMMENT THESE WHEN KECCAK IS IMPLEMENTED
    	KeccakHash.setVisible(false);
    	KeccakHash.setSelection(false);
    	setKeccakText(Messages.WizardError5);
    	KeccakOutput.setVisible(true);
    	//***
        PlatformUI.getWorkbench().getHelpSystem().setHelp(getControl(), SHA3Plugin.PLUGIN_ID + ".wizardhelp");
    }
    
    private void createInputTextGroup(Composite parent){
        GridLayout InputGroupGridLayout = new GridLayout();
        InputGroupGridLayout.numColumns = 1;

        GridData InputGroupGridData = new GridData();
        InputGroupGridData.horizontalAlignment = GridData.FILL;
        InputGroupGridData.grabExcessHorizontalSpace = true;
        InputGroupGridData.grabExcessVerticalSpace = true;
        InputGroupGridData.verticalAlignment = GridData.FILL;

        InputTextGroup = new Group(parent, SWT.NONE);
        InputTextGroup.setLayoutData(InputGroupGridData);
        InputTextGroup.setLayout(InputGroupGridLayout);
        InputTextGroup.setText(Messages.WizardMessage19);

        InputText = new Text(InputTextGroup, SWT.BORDER | SWT.MULTI | SWT.V_SCROLL);
        InputText.setLayoutData(InputGroupGridData);
        String imputtemp = "";
        InputText.setText(imputtemp);
        InputText.addListener(SWT.Modify, this);
        InputTextGroup.setVisible(true);
    }

    /**
     * Creates a new group for a verify and a hash button
     *
     * @param parent
     */
    private void createOptionGroup(Composite parent) {
        GridLayout OptionGroupGridLayout = new GridLayout();
        OptionGroupGridLayout.numColumns = 3;

        GridData OptionGroupGridData = new GridData();
        OptionGroupGridData.horizontalAlignment = GridData.FILL;
        OptionGroupGridData.grabExcessHorizontalSpace = true;
        OptionGroupGridData.grabExcessVerticalSpace = true;
        OptionGroupGridData.verticalAlignment = GridData.FILL;

        OptionGroup = new Group(parent, SWT.NONE);
        OptionGroup.setLayoutData(OptionGroupGridData);
        OptionGroup.setLayout(OptionGroupGridLayout);
        OptionGroup.setText(Messages.WizardMessage2);

        GridData CreateHashButton = new GridData();
        CreateHashButton.horizontalAlignment = GridData.FILL;
        CreateHashButton.grabExcessHorizontalSpace = true;
        CreateHashButton.grabExcessVerticalSpace = true;
        CreateHashButton.verticalAlignment = GridData.CENTER;

        CreateHash = new Button(OptionGroup, SWT.RADIO);
        CreateHash.setText(Messages.WizardMessage3);
        CreateHash.setLayoutData(CreateHashButton);
        CreateHash.addListener(SWT.Selection, this);

        GridData VerifyHashButton = new GridData();
        VerifyHashButton.horizontalAlignment = GridData.FILL;
        VerifyHashButton.grabExcessHorizontalSpace = true;
        VerifyHashButton.grabExcessVerticalSpace = true;
        VerifyHashButton.verticalAlignment = GridData.CENTER;

        VerifyHash = new Button(OptionGroup, SWT.RADIO);
        VerifyHash.setText(Messages.WizardMessage4);
        VerifyHash.setLayoutData(VerifyHashButton);
        VerifyHash.addListener(SWT.Selection, this);

        GridData SaltGridData = new GridData();
        SaltGridData.horizontalAlignment = GridData.FILL;
        SaltGridData.grabExcessHorizontalSpace = true;
        SaltGridData.grabExcessVerticalSpace = true;
        SaltGridData.verticalAlignment = GridData.CENTER;

        Salt = new Button(OptionGroup, SWT.CHECK);
        Salt.setText("Salt");
        Salt.setLayoutData(SaltGridData);
        Salt.addListener(SWT.Selection, this);

        GridData HashLabelGridData = new GridData();
        HashLabelGridData.horizontalSpan = 2;
        HashLabelGridData.horizontalAlignment = GridData.BEGINNING;
        HashLabelGridData.grabExcessHorizontalSpace = true;
        HashLabelGridData.grabExcessVerticalSpace = false;
        HashLabelGridData.verticalAlignment = GridData.CENTER;

        GridData HashValueGridData = new GridData();
        HashValueGridData.horizontalSpan = 2;
        HashValueGridData.verticalAlignment = GridData.CENTER;
        HashValueGridData.grabExcessHorizontalSpace = true;
        HashValueGridData.horizontalAlignment = GridData.FILL;

        HashValue = new Text(OptionGroup, SWT.BORDER | SWT.MULTI);
        HashValue.setLayoutData(HashValueGridData);
        String temp = "";
        HashValue.setText(temp);
        HashValue.addListener(SWT.Modify, this);
        HashValue.addVerifyListener(new VerifyListener() {
            public void verifyText(VerifyEvent e) {
                setErrorMessage(null);
                if (e.character != SWT.BS && e.character != SWT.DEL) {
                    e.text = e.text.toUpperCase();
                    /* verify the input for illegal expressions */
                    Pattern hex = Pattern.compile("[A-Fa-f0-9]+");
                    Pattern length = Pattern.compile("[A-Fa-f0-9]{1," + (getBitLength() / 4) + "}");
                    Matcher m = hex.matcher(e.text);
                    Matcher n = length.matcher(e.text);
                    if (!m.matches()) {
                        setErrorMessage(Messages.WizardError1);
                        e.doit = false;
                    } else if ((HashValue.getText().length() + 1) > getBitLength() / 4 || !n.matches()) {
                        setErrorMessage(Messages.WizardError2);
                        e.doit = false;
                    }
                }
            }

        });
        HashValue.setVisible(false);
    }

    public void createSaltGroup(Composite parent) {
        GridLayout SaltGroupGridLayout = new GridLayout();
        SaltGroupGridLayout.numColumns = 3;

        GridData SaltGroupGridData = new GridData();
        SaltGroupGridData.horizontalAlignment = GridData.FILL;
        SaltGroupGridData.grabExcessHorizontalSpace = true;
        SaltGroupGridData.grabExcessVerticalSpace = true;
        SaltGroupGridData.verticalAlignment = GridData.FILL;

        SaltGroup = new Group(parent, SWT.NONE);
        SaltGroup.setLayoutData(SaltGroupGridData);
        SaltGroup.setLayout(SaltGroupGridLayout);
        SaltGroup.setText(Messages.WizardMessage13);

        SaltValue = new Text(SaltGroup, SWT.BORDER | SWT.MULTI);
        SaltValue.setLayoutData(SaltGroupGridData);
        String temp2 = "";
        SaltValue.setText(temp2);
        SaltValue.addListener(SWT.Modify, this);
        SaltValue.addVerifyListener(new VerifyListener() {
            public void verifyText(VerifyEvent eSalt) {
                setErrorMessage(null);
                if (eSalt.character != SWT.BS && eSalt.character != SWT.DEL) {
                    eSalt.text = eSalt.text.toUpperCase();
                    /* verify the input for illegal expressions */
                    Pattern hex = Pattern.compile("[A-Fa-f0-9]+");
                    Pattern length = Pattern.compile("[A-Fa-f0-9]{1,32}");
                    Matcher m = hex.matcher(eSalt.text);
                    Matcher n = length.matcher(eSalt.text);
                    if (!m.matches()) {
                        setErrorMessage(Messages.WizardError1);
                        eSalt.doit = false;
                    } else if ((SaltValue.getText().length() + 1) > 32 || !n.matches()) {
                        setErrorMessage(Messages.WizardError3);
                        eSalt.doit = false;
                    } else
                        setErrorMessage(Messages.WizardError4);
                }
            }

        });
        SaltGroup.setVisible(false);
    }


    /**
     * Creates a drop-down list for all algorithms For adding a new algorithm just do another
     * AlgorithmCombo.add("<algorithm-name>"); at the end of the method
     *
     * @param parent
     */
    
    
    private void createAlgorithmGroup(Composite parent) {
        GridLayout AlgorithmGroupGridLayout = new GridLayout();
        AlgorithmGroupGridLayout.numColumns =2;
        AlgorithmGroupGridLayout.makeColumnsEqualWidth = false;
        

        GridData AlgorithmGroupGridData = new GridData();
        AlgorithmGroupGridData.horizontalAlignment = GridData.FILL;
        AlgorithmGroupGridData.grabExcessHorizontalSpace = true;
        AlgorithmGroupGridData.grabExcessVerticalSpace = true;
        AlgorithmGroupGridData.verticalAlignment = GridData.FILL;

        AlgorithmGroup = new Group(parent, SWT.NONE);
        AlgorithmGroup.setLayoutData(AlgorithmGroupGridData);
        AlgorithmGroup.setLayout(AlgorithmGroupGridLayout);
        AlgorithmGroup.setText(Messages.WizardMessage9);

        GridData EchoButton = new GridData();
        EchoButton.horizontalAlignment = GridData.FILL;
        EchoButton.grabExcessHorizontalSpace = true;
        EchoButton.grabExcessVerticalSpace = true;
        EchoButton.verticalAlignment = GridData.FILL;
        EchoButton.widthHint = 200;

        EchoHash = new Button(AlgorithmGroup, SWT.CHECK);
        EchoHash.setText(Messages.WizardMessage14);
        EchoHash.setLayoutData(EchoButton);
        EchoHash.addListener(SWT.Selection, this);
        
        GridData EchoText = new GridData();
        EchoText.horizontalAlignment = GridData.FILL;
        EchoText.grabExcessHorizontalSpace = true;
        EchoText.grabExcessVerticalSpace = true;
        EchoText.verticalAlignment = GridData.FILL;
        
        EchoOutput = new Text(AlgorithmGroup, SWT.READ_ONLY | SWT.BORDER);
        EchoOutput.setLayoutData(EchoText);
        String tempEcho = "";
        EchoOutput.setText(tempEcho);
        EchoOutput.addListener(SWT.Modify, this);
        EchoOutput.setVisible(false);

        GridData JHButton = new GridData();
        JHButton.horizontalAlignment = GridData.FILL;
        JHButton.grabExcessHorizontalSpace = true;
        JHButton.grabExcessVerticalSpace = true;
        JHButton.verticalAlignment = GridData.FILL;
        JHButton.widthHint = 200;

        JHHash = new Button(AlgorithmGroup, SWT.CHECK);
        JHHash.setText(Messages.WizardMessage15);
        JHHash.setLayoutData(JHButton);
        JHHash.addListener(SWT.Selection, this);
        
        GridData JHText = new GridData();
        JHText.horizontalAlignment = GridData.FILL;
        JHText.grabExcessHorizontalSpace = false;
        JHText.grabExcessVerticalSpace = true;
        JHText.verticalAlignment = GridData.FILL;
        
        
        JHOutput = new Text(AlgorithmGroup, SWT.READ_ONLY | SWT.BORDER);
        JHOutput.setLayoutData(JHText);
        String tempJH = "";
        JHOutput.setText(tempJH);
        JHOutput.addListener(SWT.Modify, this);
        JHOutput.setVisible(false);
        

        GridData SkeinButton = new GridData();
        SkeinButton.horizontalAlignment = GridData.FILL;
        SkeinButton.grabExcessHorizontalSpace = true;
        SkeinButton.grabExcessVerticalSpace = true;
        SkeinButton.verticalAlignment = GridData.FILL;
        SkeinButton.widthHint = 200;

        SkeinHash = new Button(AlgorithmGroup, SWT.CHECK);
        SkeinHash.setText(Messages.WizardMessage16);
        SkeinHash.setLayoutData(SkeinButton);
        SkeinHash.addListener(SWT.Selection, this);
        
        GridData SkeinText = new GridData();
        SkeinText.horizontalAlignment = GridData.FILL;
        SkeinText.grabExcessHorizontalSpace = false;
        SkeinText.grabExcessVerticalSpace = true;
        SkeinText.verticalAlignment = GridData.FILL;
        
        SkeinOutput = new Text(AlgorithmGroup, SWT.READ_ONLY | SWT.BORDER);
        SkeinOutput.setLayoutData(AlgorithmGroupGridData);
        String tempSkein = "";
        SkeinOutput.setText(tempSkein);
        SkeinOutput.addListener(SWT.Modify, this);
        SkeinOutput.setVisible(false);
        
        
        GridData BlakeButton = new GridData();
        BlakeButton.horizontalAlignment = GridData.FILL;
        BlakeButton.grabExcessHorizontalSpace = true;
        BlakeButton.grabExcessVerticalSpace = true;
        BlakeButton.verticalAlignment = GridData.FILL;

        BlakeHash = new Button(AlgorithmGroup, SWT.CHECK);
        BlakeHash.setText(Messages.WizardMessage20);
        BlakeHash.setLayoutData(BlakeButton);
        BlakeHash.addListener(SWT.Selection, this);
        
        GridData BlakeText = new GridData();
        BlakeText.horizontalAlignment = GridData.FILL;
        BlakeText.grabExcessHorizontalSpace = false;
        BlakeText.grabExcessVerticalSpace = true;
        BlakeText.verticalAlignment = GridData.FILL;
        
        BlakeOutput = new Text(AlgorithmGroup, SWT.READ_ONLY | SWT.BORDER);
        BlakeOutput.setLayoutData(AlgorithmGroupGridData);
        String tempBlake = "";
        BlakeOutput.setText(tempBlake);
        BlakeOutput.addListener(SWT.Modify, this);
        BlakeOutput.setVisible(false);
        
        GridData KeccakButton = new GridData();
        KeccakButton.horizontalAlignment = GridData.FILL;
        KeccakButton.grabExcessHorizontalSpace = true;
        KeccakButton.grabExcessVerticalSpace = true;
        KeccakButton.verticalAlignment = GridData.FILL;
        KeccakButton.widthHint = 200;

        KeccakHash = new Button(AlgorithmGroup, SWT.CHECK);
        KeccakHash.setText(Messages.WizardMessage21);
        KeccakHash.setLayoutData(KeccakButton);
        KeccakHash.addListener(SWT.Selection, this);
        
        GridData KeccakText = new GridData();
        KeccakText.horizontalAlignment = GridData.FILL;
        KeccakText.grabExcessHorizontalSpace = false;
        KeccakText.grabExcessVerticalSpace = true;
        KeccakText.verticalAlignment = GridData.FILL;
        
        
        KeccakOutput = new Text(AlgorithmGroup, SWT.READ_ONLY | SWT.BORDER);
        KeccakOutput.setLayoutData(KeccakText);
        String tempKeccak = "";
        KeccakOutput.setText(tempKeccak);
        KeccakOutput.addListener(SWT.Modify, this);
        KeccakOutput.setVisible(false);
        
        GridData GroestlButton = new GridData();
        GroestlButton.horizontalAlignment = GridData.FILL;
        GroestlButton.grabExcessHorizontalSpace = true;
        GroestlButton.grabExcessVerticalSpace = true;
        GroestlButton.verticalAlignment = GridData.FILL;
        GroestlButton.widthHint = 200;

        GroestlHash = new Button(AlgorithmGroup, SWT.CHECK);
        GroestlHash.setText(Messages.WizardMessage22);
        GroestlHash.setLayoutData(GroestlButton);
        GroestlHash.addListener(SWT.Selection, this);
        
        GridData GroestlText = new GridData();
        GroestlText.horizontalAlignment = GridData.FILL;
        GroestlText.grabExcessHorizontalSpace = false;
        GroestlText.grabExcessVerticalSpace = true;
        GroestlText.verticalAlignment = GridData.FILL;
        
        
        GroestlOutput = new Text(AlgorithmGroup, SWT.READ_ONLY | SWT.BORDER);
        GroestlOutput.setLayoutData(GroestlText);
        String tempGroestl = "";
        JHOutput.setText(tempGroestl);
        GroestlOutput.addListener(SWT.Modify, this);
        GroestlOutput.setVisible(false);
        
        
        
    }
    
    protected void createSubmitGroup(Composite parent){
        GridLayout SubmitGroupGridLayout = new GridLayout();
        SubmitGroupGridLayout.numColumns =2;

        GridData SubmitGroupGridData = new GridData();
        SubmitGroupGridData.horizontalAlignment = GridData.FILL;
        SubmitGroupGridData.grabExcessHorizontalSpace = true;
        SubmitGroupGridData.grabExcessVerticalSpace = true;
        SubmitGroupGridData.verticalAlignment = GridData.FILL;

        SubmitGroup = new Group(parent, SWT.NONE);
        SubmitGroup.setLayoutData(SubmitGroupGridData);
        SubmitGroup.setLayout(SubmitGroupGridLayout);
        SubmitGroup.setText(Messages.WizardMessage17);

        GridData SubmitButton = new GridData();
        SubmitButton.horizontalAlignment = GridData.FILL;
        SubmitButton.grabExcessHorizontalSpace = true;
        SubmitButton.grabExcessVerticalSpace = true;
        SubmitButton.verticalAlignment = GridData.FILL;

        Submit = new Button(SubmitGroup, SWT.PUSH);
        Submit.setText(Messages.WizardMessage18);
        Submit.setLayoutData(SubmitButton);
        Submit.addListener(SWT.Selection, this);
    }

    /**
     * Creates a drop-down list for the bitlength
     *
     * @param parent
     */
    protected void createBitlengthGroup(Composite parent) {
        bitlengthGroup = new Group(parent, SWT.NONE);
        GridLayout BitlengthGroupGridLayout = new GridLayout();
        BitlengthGroupGridLayout.numColumns = 1;

        GridData BitlengthGroupGridData = new GridData();
        BitlengthGroupGridData.horizontalAlignment = GridData.FILL;
        BitlengthGroupGridData.grabExcessHorizontalSpace = false;
        BitlengthGroupGridData.grabExcessVerticalSpace = false;
        BitlengthGroupGridData.verticalAlignment = SWT.TOP;

        bitlengthGroup.setLayoutData(BitlengthGroupGridData);
        bitlengthGroup.setLayout(BitlengthGroupGridLayout);

        BitlengthListLabel = new Label(bitlengthGroup, SWT.NONE);
        GridData BitlengthLabelGridData = new GridData();
        BitlengthLabelGridData.horizontalAlignment = GridData.FILL;
        BitlengthLabelGridData.grabExcessHorizontalSpace = false;
        BitlengthLabelGridData.grabExcessVerticalSpace = false;
        BitlengthLabelGridData.verticalAlignment = GridData.CENTER;

        BitlengthListLabel.setText(Messages.WizardMessage10);
        BitlengthListLabel.setLayoutData(BitlengthLabelGridData);

        BitlengthCombo = new Combo(bitlengthGroup, SWT.BORDER | SWT.READ_ONLY);
        GridData BitlengthComboGridData = new GridData();
        BitlengthComboGridData.horizontalAlignment = GridData.GRAB_HORIZONTAL;
        BitlengthComboGridData.grabExcessHorizontalSpace = false;
        BitlengthComboGridData.grabExcessVerticalSpace = true;
        BitlengthComboGridData.verticalAlignment = GridData.CENTER;

        BitlengthCombo.setLayoutData(BitlengthComboGridData);
        BitlengthCombo.addListener(SWT.Selection, this);
    }

    /**
     * This method is responsible for all events that may happen in the wizard
     */
    public void handleEvent(Event event) {
        if (event.widget == VerifyHash) {
        	EchoHash.setVisible(true);
        	EchoHash.setSelection(false);
        	EchoOutput.setVisible(false);
        	EchoSelect = 0;
        	setEchoText("");
        	JHHash.setVisible(true);
        	JHHash.setSelection(false);
        	JHOutput.setVisible(false);
        	JHSelect = 0;
        	setJHText("");
        	SkeinHash.setVisible(true);
        	SkeinHash.setSelection(false);
        	SkeinOutput.setVisible(false);
        	SkeinSelect = 0;
        	setSkeinText("");
        	BlakeHash.setVisible(true);
        	BlakeHash.setSelection(false);
        	BlakeOutput.setVisible(false);
        	BlakeSelect = 0;
        	setBlakeText("");
        	KeccakHash.setVisible(true);
        	KeccakHash.setSelection(false);
        	KeccakOutput.setVisible(false);
        	KeccakSelect = 0;
        	setKeccakText("");
        	GroestlHash.setVisible(true);
        	GroestlHash.setSelection(false);
        	GroestlOutput.setVisible(false);
        	GroestlSelect = 0;
        	setGroestlText("");
            Mode = true;
            HashValue.setEnabled(true);
            HashValue.setVisible(true);
        } else if (event.widget == CreateHash) {
        	EchoHash.setVisible(true);
        	EchoHash.setSelection(false);
        	EchoOutput.setVisible(false);
        	EchoSelect = 0;
        	setEchoText("");
        	JHHash.setVisible(true);
        	JHHash.setSelection(false);
        	JHOutput.setVisible(false);
        	JHSelect = 0;
        	setJHText("");
        	SkeinHash.setVisible(true);
        	SkeinHash.setSelection(false);
        	SkeinOutput.setVisible(false);
        	SkeinSelect = 0;
        	setSkeinText("");
        	BlakeHash.setVisible(true);
        	BlakeHash.setSelection(false);
        	BlakeOutput.setVisible(false);
        	BlakeSelect = 0;
        	setBlakeText("");
        	KeccakHash.setVisible(true);
        	KeccakHash.setSelection(false);
        	KeccakOutput.setVisible(false);
        	KeccakSelect = 0;
        	setKeccakText("");
        	GroestlHash.setVisible(true);
        	GroestlHash.setSelection(false);
        	GroestlOutput.setVisible(false);
        	GroestlSelect = 0;
        	setGroestlText("");
            Mode = false;
            HashValue.setEnabled(false);
            HashValue.setVisible(false);
        }
        if (event.widget == HashValue) {
            Hash = HashValue.getText();
        }
        if (event.widget == SaltValue) {
            SaltEcho = SaltValue.getText();
        }
        if(event.widget == InputText){
        	InputEcho = InputText.getText();
        }
        if(event.widget == EchoHash){
            if(EchoHash.getSelection()){
        		EchoOutput.setVisible(true);
        		EchoSelect= 1;
        	}
        	else{
        		EchoOutput.setVisible(false);
        		EchoSelect = 0;
        	}
        }
        if(event.widget == JHHash){
            if(JHHash.getSelection()){
        		JHOutput.setVisible(true);
        		JHSelect = 1;
        	}
        	else{
        		JHOutput.setVisible(false);
        		JHSelect = 0;
        	}
        }
        if(event.widget == SkeinHash){
            if(SkeinHash.getSelection()){
        		SkeinOutput.setVisible(true);
        		SkeinSelect = 1;
        	}
        	else{
        		SkeinOutput.setVisible(false);
        		SkeinSelect = 0;
        	}
        }
        if(event.widget == BlakeHash){
            if(BlakeHash.getSelection()){
        		BlakeOutput.setVisible(true);
        		BlakeSelect = 1;
        	}
        	else{
        		BlakeOutput.setVisible(false);
        		BlakeSelect = 0;
        	}
        }
        if(event.widget == KeccakHash){
            if(KeccakHash.getSelection()){
        		KeccakOutput.setVisible(true);
        		KeccakSelect= 1;
        	}
        	else{
        		KeccakOutput.setVisible(false);
        		KeccakSelect = 0;
        	}
        }
        if(event.widget == GroestlHash){
            if(GroestlHash.getSelection()){
        		GroestlOutput.setVisible(true);
        		GroestlSelect= 1;
        	}
        	else{
        		GroestlOutput.setVisible(false);
        		GroestlSelect = 0;
        	}
        }
        if (event.widget == Salt) {
        	EchoHash.setVisible(true);
        	EchoHash.setSelection(false);
        	EchoOutput.setVisible(false);
        	EchoSelect = 0;
        	setEchoText("");
        	JHHash.setVisible(true);
        	JHHash.setSelection(false);
        	JHOutput.setVisible(false);
        	JHSelect = 0;
        	setJHText("");
        	SkeinHash.setVisible(true);
        	SkeinHash.setSelection(false);
        	SkeinOutput.setVisible(false);
        	SkeinSelect = 0;
        	setSkeinText("");
        	BlakeHash.setVisible(true);
        	BlakeHash.setSelection(false);
        	BlakeOutput.setVisible(false);
        	BlakeSelect = 0;
        	setBlakeText("");
        	KeccakHash.setVisible(true);
        	KeccakHash.setSelection(false);
        	KeccakOutput.setVisible(false);
        	KeccakSelect = 0;
        	setKeccakText("");
        	GroestlHash.setVisible(true);
        	GroestlHash.setSelection(false);
        	GroestlOutput.setVisible(false);
        	GroestlSelect = 0;
        	setGroestlText("");
            if (Salt.getSelection()) {
                SaltGroup.setVisible(true);
            } else
                SaltGroup.setVisible(false);
        }
        
        if(event.widget == Submit){
        	if(CreateHash.getSelection()){
        		computeHash();
        	}
        	else{
        		verifyHash();
        	}
        }
        if (event.widget == BitlengthCombo) {
        	EchoHash.setVisible(true);
        	EchoHash.setSelection(false);
        	EchoOutput.setVisible(false);
        	EchoSelect = 0;
        	setEchoText("");
        	JHHash.setVisible(true);
        	JHHash.setSelection(false);
        	JHOutput.setVisible(false);
        	JHSelect = 0;
        	setJHText("");
        	SkeinHash.setVisible(true);
        	SkeinHash.setSelection(false);
        	SkeinOutput.setVisible(false);
        	SkeinSelect = 0;
        	setSkeinText("");
        	BlakeHash.setVisible(true);
        	BlakeHash.setSelection(false);
        	BlakeOutput.setVisible(false);
        	BlakeSelect = 0;
        	setBlakeText("");
        	KeccakHash.setVisible(true);
        	KeccakHash.setSelection(false);
        	KeccakOutput.setVisible(false);
        	KeccakSelect = 0;
        	setKeccakText("");
        	GroestlHash.setVisible(true);
        	GroestlHash.setSelection(false);
        	GroestlOutput.setVisible(false);
        	GroestlSelect = 0;
        	setGroestlText("");
            if (BitlengthCombo.getSelectionIndex() == 0) {
            	SkeinHash.setVisible(false);
            	SkeinHash.setSelection(false);
            	setSkeinText(Messages.WizardError5);
            	SkeinOutput.setVisible(true);
            	//***UNCOMMENT THESE WHEN KECCAK IS IMPLEMENTED
            	KeccakHash.setVisible(false);
            	KeccakHash.setSelection(false);
            	setKeccakText(Messages.WizardError5);
            	KeccakOutput.setVisible(true);
            	//***
                Bitlength = 0;
            } else if (BitlengthCombo.getSelectionIndex() == 1) {
            	//***UNCOMMENT THESE WHEN KECCAK IS IMPLEMENTED
            	KeccakHash.setVisible(false);
            	KeccakHash.setSelection(false);
            	setKeccakText(Messages.WizardError5);
            	KeccakOutput.setVisible(true);
            	//***
                Bitlength = 1;
            } else if (BitlengthCombo.getSelectionIndex() == 2) {
            	SkeinHash.setVisible(false);
            	SkeinHash.setSelection(false);
            	setSkeinText(Messages.WizardError5);
            	SkeinOutput.setVisible(true);
            	//***UNCOMMENT THESE WHEN KECCAK IS IMPLEMENTED
            	KeccakHash.setVisible(false);
            	KeccakHash.setSelection(false);
            	setKeccakText(Messages.WizardError5);
            	KeccakOutput.setVisible(true);
            	//***
                Bitlength = 2;
            } else if (BitlengthCombo.getSelectionIndex() == 3) {
            	//***UNCOMMENT THESE WHEN KECCAK IS IMPLEMENTED
            	KeccakHash.setVisible(false);
            	KeccakHash.setSelection(false);
            	setKeccakText(Messages.WizardError5);
            	KeccakOutput.setVisible(true);
            	//***
            	Bitlength = 3;
            } else if (BitlengthCombo.getSelectionIndex() == 4) {
            	EchoHash.setVisible(false);
            	EchoHash.setSelection(false);
            	setEchoText(Messages.WizardError5);
            	EchoOutput.setVisible(true);
            	JHHash.setVisible(false);
            	JHHash.setSelection(false);
            	setJHText(Messages.WizardError5);
            	JHOutput.setVisible(true);
            	BlakeHash.setVisible(false);
            	BlakeHash.setSelection(false);
            	setBlakeText(Messages.WizardError5);
            	BlakeOutput.setVisible(true);
            	GroestlHash.setVisible(false);
            	GroestlHash.setSelection(false);
            	setGroestlText(Messages.WizardError5);
            	GroestlOutput.setVisible(true);
            	//***UNCOMMENT THESE WHEN KECCAK IS IMPLEMENTED
            	KeccakHash.setVisible(false);
            	KeccakHash.setSelection(false);
            	setKeccakText(Messages.WizardError5);
            	KeccakOutput.setVisible(true);
            	//***
            	Bitlength = 4;
            }
        }
        setPageComplete(mayFinish());
    }
    
    

    /**
     * Returns the entered hash value
     *
     * @return
     */
    public String getHashValue() {
        return Hash;
    }

    /**
     * Returns the name of the chosen algorithm
     *
     * @return
     */
    public String getEchoSelect() {
        String echoOn = "";
        if(EchoSelect == 1){
        	echoOn = "ON";
        }
        else{
        	echoOn = "OFF";
        }
        return echoOn;
    }
    public String getJHSelect() {
        String JHOn = "";
        if(JHSelect == 1){
        	JHOn = "ON";
        }
        else{
        	JHOn = "OFF";
        }
        return JHOn;
    }
    public String getSkeinSelect() {
        String skeinOn = "";
        if(SkeinSelect == 1){
        	skeinOn = "ON";
        }
        else{
        	skeinOn = "OFF";
        }
        return skeinOn;
    }
    
    public String getBlakeSelect() {
        String BlakeOn = "";
        if(BlakeSelect == 1){
        	BlakeOn = "ON";
        }
        else{
        	BlakeOn = "OFF";
        }
        return BlakeOn;
    }
    
    public String getKeccakSelect() {
        String KeccakOn = "";
        if(KeccakSelect == 1){
        	KeccakOn = "ON";
        }
        else{
        	KeccakOn = "OFF";
        }
        return KeccakOn;
    }
    public String getGreostlSelect() {
        String GroestlOn = "";
        if(GroestlSelect == 1){
        	GroestlOn = "ON";
        }
        else{
        	GroestlOn = "OFF";
        }
        return GroestlOn;
    }
    public String getSalt() {
        return SaltEcho;
    }
    
    public String getInputText(){
    	return InputEcho;
    }

    /**
     * This method returns the chosen bitlength
     *
     * @return
     */
    public int getBitLength() {
            switch (Bitlength) {
                case 0:
                    Bitlength = 224;
                    break;
                case 1:
                    Bitlength = 256;
                    break;
                case 2:
                    Bitlength = 384;
                    break;
                case 3:
                    Bitlength = 512;
                    break;
                case 4:
                	Bitlength = 1024;
        }
        return Bitlength;
    }

    /**
     * @return false = createHash, true = verifyHash
     */
    public String getMode() {
        if (Mode == false)
            return "CreateHash";
        else
            return "VerifyHash";
    }
    
    
    public void setEchoText(String HashDisplay){
    	EchoOutput.setText(HashDisplay);
    }
    
    public void setJHText(String HashDisplay){
    	JHOutput.setText(HashDisplay);
    }
    
    public void setSkeinText(String HashDisplay){
    	SkeinOutput.setText(HashDisplay);
    }
    
    public void setBlakeText(String HashDisplay){
    	BlakeOutput.setText(HashDisplay);
    }
    public void setKeccakText(String HashDisplay){
    	KeccakOutput.setText(HashDisplay);
    }
    public void setGroestlText(String HashDisplay){
    	GroestlOutput.setText(HashDisplay);
    }
    
    private boolean mayFinish() {
        /*
         * if (SHA3Type == -1) return false; if (Bitlength == -1) return false; if (CreateHash.getSelection()==false &&
         * VerifyHash.getSelection()==false) return false;
         */
        return true;
    }
    
    public void verifyHash(){    	
        byte[] EchoHashValue = null;
        byte[] JHHashValue = null;
        byte[] SkeinHashValue = null;
        byte[] BlakeHashValue = null;
        byte[] KeccakHashValue = null;
        byte[] GreostlHashValue = null;
        int Bitlength = getBitLength();
        String Salt = getSalt();
        String Input = getInputText();
        String compText = getHashValue();
    	
    	
    	ECHOAction runECHO = new ECHOAction();
		if (Salt.compareTo("") == 0)
			EchoHashValue = runECHO.run(Bitlength, Input);
		else
			EchoHashValue = runECHO.run(Bitlength, Input,Salt);
		//EchoOutput.setVisible(true);
		if(toHex(EchoHashValue).compareTo(compText) == 0){
	    	setEchoText(Messages.WizardMessage11);
		}
		else{
			setEchoText(Messages.WizardMessage12);
		}
		JHAction runJH = new JHAction();
		JHHashValue = runJH.run(Bitlength, Input);
    	//JHOutput.setVisible(true);
		if(toHex(JHHashValue).compareTo(compText) == 0){
	    	setJHText(Messages.WizardMessage11);
		}
		else{
			setJHText(Messages.WizardMessage12);
		}
		
      	SkeinAction runSkein = new SkeinAction();
      	SkeinHashValue = runSkein.run(Bitlength, Input, Bitlength);
    	//SkeinOutput.setVisible(true);
      	if(toHex(SkeinHashValue).compareTo(compText) == 0){
        	setSkeinText(Messages.WizardMessage11);
      	}
      	else{
      		setSkeinText(Messages.WizardMessage12);
      	}
      	
		BLAKEAction runBlake = new BLAKEAction();
		if(Salt.compareTo("") == 0){
			BlakeHashValue = runBlake.run(Bitlength, Input);
		}
		else{
			BlakeHashValue = runBlake.run(Bitlength, Input,Salt);
		}
    	//BlakeOutput.setVisible(true);
		if(toHex(BlakeHashValue).compareTo(compText) == 0){
	    	setBlakeText(Messages.WizardMessage11);
		}
		else{
			setBlakeText(Messages.WizardMessage12);
		}
		/*
      	KeccakAction runKeccak = new KeccakAction();
      	KeccakHashValue = runKeccak.run(Bitlength, Input, Bitlength);
    	//KeccakOutput.setVisible(true);
      	if(toHex(KeccakHashValue).compareTo(compText) == 0){
        	setKeccakText(Messages.WizardMessage11);
      	}
      	else{
      		setKeccakText(Messages.WizardMessage12);
      	}
      	*/
      	GroestlAction runGroestl = new GroestlAction();
      	GroestlHashValue = runGroestl.run(Bitlength, Input, Bitlength);
    	//GroestlOutput.setVisible(true);
      	if(toHex(GroestlHashValue).compareTo(compText) == 0){
        	setGreostlText(Messages.WizardMessage11);
      	}
      	else{
      		setGroestlText(Messages.WizardMessage12);
      	}
    
    }
    
    
    public void computeHash(){
                /* Get all the important information of the wizard */
                int Bitlength = getBitLength();
                String EchoOn = getEchoSelect();
                String JHOn = getJHSelect();
                String SkeinOn = getSkeinSelect();
                String BlakeOn = getBlakeSelect();
                String Mode = getMode();
                byte[] EchoHashValue = null;
                byte[] JHHashValue = null;
                byte[] SkeinHashValue = null;
                byte[] BlakeHashValue = null;
                byte[] KeccakHashValue = null;
                byte[] GroestlHashValue = null;
                byte[] TestString = "HelloTest".getBytes();
                String Salt = getSalt();
                String Input = getInputText();
                /* Check if the hash shall be created or verified */
                if (Mode.compareTo("CreateHash") == 0) {
                    //if (EchoOn.compareTo("ON") == 0) {
                    		ECHOAction runECHO = new ECHOAction();
                    		if (Salt.compareTo("") == 0)
                    			EchoHashValue = runECHO.run(Bitlength, Input);
                    		else
                    			EchoHashValue = runECHO.run(Bitlength, Input,Salt);
                    		setEchoText(toHex(EchoHashValue));
                    //} if (JHOn.compareTo("ON") == 0) {
                    		JHAction runJH = new JHAction();
                    		JHHashValue = runJH.run(Bitlength, Input);
                    		setJHText(toHex(JHHashValue));
                    //} if (SkeinOn.compareTo("ON") == 0) {
                          	SkeinAction runSkein = new SkeinAction();
                          	SkeinHashValue = runSkein.run(Bitlength, Input, Bitlength);
                          	setSkeinText(toHex(SkeinHashValue));
                    //}
                //} if (BlakeOn.compareTo("ON") == 0) {
                		BLAKEAction runBlake = new BLAKEAction();
                		if(Salt.compareTo("") == 0){
                			BlakeHashValue = runBlake.run(Bitlength, Input);
                		}
                		else{
                			BlakeHashValue = runBlake.run(Bitlength, Input,Salt);
                		}
                		setBlakeText(toHex(BlakeHashValue));
                		/*
                		KeccakAction runKeccak = new KeccakAction();
                		KeccakHashValue = runKeccak.run(Bitlength, Input);
                		setKeccakText(toHex(KeccakHashValue));
                		*/
                		GroestlAction runGroestl = new GroestlAction();
                		GroestlHashValue = runGroestl.run(Bitlength, Input);
                		setGroestlText(toHex(GroestlHashValue));
                //}
                }
    }
    
    /**
     * Changes the byte array to a hex string
     *
     * @param bytes
     * @return
     */
    public static String toHex(final byte[] bytes) {
        final StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (int i = 0; i < bytes.length; i++) {
            sb.append(String.format("%02X", bytes[i] & UNSIGNED_BYTE_MASK));
        }
        return sb.toString();
    }
    
    
    
}
