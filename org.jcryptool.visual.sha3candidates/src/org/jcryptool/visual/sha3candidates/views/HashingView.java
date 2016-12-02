package org.jcryptool.visual.sha3candidates.views;

import java.io.File;  
import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.util.ArrayList;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.jcryptool.visual.sha3candidates.algorithms.BLAKE.Blake_Algorithm.IV224;
import static org.jcryptool.visual.sha3candidates.algorithms.BLAKE.Blake_Algorithm.c32;

import org.bouncycastle.crypto.digests.GOST3411Digest;
import org.bouncycastle.crypto.digests.MD2Digest;
import org.bouncycastle.crypto.digests.MD4Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.digests.TigerDigest;
import org.bouncycastle.crypto.digests.WhirlpoolDigest;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.bouncycastle.jcajce.provider.digest.Skein;
import org.bouncycastle.util.encoders.Hex;
import org.eclipse.core.runtime.FileLocator;
import org.eclipse.swt.SWT;
///////////////////
import org.eclipse.swt.browser.Browser;  
import org.eclipse.swt.browser.CloseWindowListener;  
import org.eclipse.swt.browser.LocationAdapter;  
import org.eclipse.swt.browser.LocationEvent;  
import org.eclipse.swt.browser.OpenWindowListener;  
import org.eclipse.swt.browser.ProgressEvent;  
import org.eclipse.swt.browser.ProgressListener;  
import org.eclipse.swt.browser.StatusTextEvent;  
import org.eclipse.swt.browser.StatusTextListener;  
import org.eclipse.swt.browser.TitleEvent;  
import org.eclipse.swt.browser.TitleListener;  
import org.eclipse.swt.browser.WindowEvent;  
/////////////////////
import org.eclipse.swt.custom.CLabel;
import org.eclipse.swt.custom.ST;
import org.eclipse.swt.custom.ScrolledComposite;
import org.eclipse.swt.custom.StyleRange;
import org.eclipse.swt.custom.StyledText;
import org.eclipse.swt.events.FocusAdapter;
import org.eclipse.swt.events.FocusEvent;
import org.eclipse.swt.events.KeyAdapter;
import org.eclipse.swt.events.KeyEvent;
import org.eclipse.swt.events.ModifyEvent;
import org.eclipse.swt.events.ModifyListener;
import org.eclipse.swt.events.MouseAdapter;
import org.eclipse.swt.events.MouseEvent;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.graphics.Point;
import org.eclipse.swt.layout.FillLayout;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Combo;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Group;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Menu;
import org.eclipse.swt.widgets.MenuItem;
import org.eclipse.swt.widgets.TabFolder;
import org.eclipse.swt.widgets.TabItem;
import org.eclipse.swt.widgets.Text;
import org.eclipse.ui.part.ViewPart;
import org.eclipse.wb.swt.SWTResourceManager;
import org.jcryptool.core.logging.utils.LogUtil;
import org.jcryptool.visual.sha3candidates.HashingPlugin;
import org.jcryptool.visual.sha3candidates.algorithms.HashFunction;
import org.jcryptool.visual.sha3candidates.algorithms.ECHO.ECHOAction;
import org.jcryptool.visual.sha3candidates.algorithms.JH.JHAction;
import org.jcryptool.visual.sha3candidates.algorithms.BLAKE.Blake_Action;
import static org.jcryptool.visual.sha3candidates.algorithms.BLAKE.Blake_Algorithm.IV224;
////////
import org.jcryptool.visual.sha3candidates.algorithms.BLAKE.Blake_tab;
import org.jcryptool.visual.sha3candidates.algorithms.BLAKE.Blake_tab0;
import org.jcryptool.visual.sha3candidates.algorithms.BLAKE.Blake_tab1;
import org.jcryptool.visual.sha3candidates.algorithms.BLAKE.Blake_tab2;
import org.jcryptool.visual.sha3candidates.algorithms.BLAKE.Blake_tab3;
////////////
import org.eclipse.swt.widgets.Table;
import org.eclipse.swt.widgets.TableColumn;
import org.eclipse.swt.widgets.TableItem;


public class HashingView extends ViewPart {

	/**
	 * The ID of the view as specified by the extension.
	 */
	public static final String ID = "org.jcryptool.visual.sha3candidates.views.HashingView"; //$NON-NLS-1$
	private static final int OUTPUT_SEPERATOR = 144;

	private org.jcryptool.visual.sha3candidates.algorithms.HashFunction hash = org.jcryptool.visual.sha3candidates.algorithms.HashFunction.BLAKE224;
	private String hashInputValueHex = ""; //$NON-NLS-1$
	private String hashOutputValueHex = ""; //$NON-NLS-1$
	private String page="file:///C:/workspace1/org.jcryptool.visual.sha3candidates/nl/en/help/content/ECHOTutorial.html";
	private Browser Hashpage;
	private Table table;
	private Table table1;
	private StyledText styledTextDescription;
	private StyleRange header;
	private Text textInput;
	private Text textHashInput;
	private Text textOutput;
	private Text textHashOutput;
	private StyledText textDifference;
	private Combo comboHash;
	private Button btnHexadezimal;
	private Button btnDezimal;
	private Button btnBinary;
	private Button btnChanged;
	private Button btnUnchanged;	
	private TabFolder tabFolder;
	private Blake_tab0 blake_tab0;
	private Blake_tab1 blake_tab1;
	private Blake_tab2 blake_tab2;
	private Blake_tab3 blake_tab3;
	private Blake_Action BLAKE224;
	/**
	 * The constructor.
	 */
	public HashingView() {
	}

	@Override
	public void createPartControl(Composite parent) {

		ScrolledComposite scrolledComposite = new ScrolledComposite(parent, SWT.BORDER | SWT.H_SCROLL | SWT.V_SCROLL);
		scrolledComposite.setExpandHorizontal(true);
		scrolledComposite.setExpandVertical(true);
		scrolledComposite.setBounds(10, 10, 1600, 800);
		Composite compositeMain = new Composite(scrolledComposite, SWT.NONE);
		compositeMain.setBounds(10, 10, 1600, 800);
		
		styledTextDescription = new StyledText(compositeMain, SWT.BORDER | SWT.READ_ONLY | SWT.WRAP);
		styledTextDescription.setBounds(10, 10, 400, 50);
		styledTextDescription.addFocusListener(new FocusAdapter() {
			@Override
			public void focusLost(FocusEvent e) {
				styledTextDescription.setSelection(0, 0);
			}
		});
		styledTextDescription.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.stateMask == SWT.CTRL && e.keyCode == 'a') {
					styledTextDescription.selectAll();
				}
			}
		});
		styledTextDescription.setEditable(false);
		GridData gd_styledTextDescription = new GridData(SWT.FILL, SWT.UP, true, false, 4, 1);
		gd_styledTextDescription.widthHint = 300;
		gd_styledTextDescription.heightHint = 60;
		styledTextDescription.setLayoutData(gd_styledTextDescription);
		styledTextDescription.setText(Messages.HashingView_0 + Messages.HashingView_1);

		
		Group Hashalgorithm = new Group(compositeMain,  SWT.FILL | SWT.H_SCROLL);
		Hashalgorithm.setBounds(420, 0,  1500, 810);
		Hashalgorithm.setText("Inside Hash Function");

		tabFolder= new TabFolder(Hashalgorithm, SWT.FILL | SWT.H_SCROLL); 
		tabFolder.setBounds(10, 20, 1480, 800);
//		tabFolder.setVisible(false);
		Group tabpage0 = new Group(tabFolder, SWT.NONE);
		tabpage0.setBounds(10, 10, 1470, 800);		
		TabItem tabItem0 = new TabItem(tabFolder, SWT.NONE);
		tabItem0.setText("Initialization");
		tabItem0.setControl(tabpage0);
		
		Group tabpage1 = new Group(tabFolder, SWT.NONE);
		tabpage1.setBounds(10, 10, 1470, 800);		
		TabItem tabItem1 = new TabItem(tabFolder, SWT.NONE);
		tabItem1.setText("Compressing");
		tabItem1.setControl(tabpage1);
		
		Group tabpage2 = new Group(tabFolder, SWT.NONE);
		tabpage2.setBounds(10, 20, 1470, 800);		
		TabItem tabItem2 = new TabItem(tabFolder, SWT.NONE);
		tabItem2.setText("Sigma");
		tabItem2.setControl(tabpage2);
		
		Group tabpage3 = new Group(tabFolder, SWT.NONE);
		tabpage3.setBounds(10, 10, 1470, 800);		
		TabItem tabItem3 = new TabItem(tabFolder, SWT.NONE);
		tabItem3.setText("Output");
		tabItem3.setControl(tabpage3);
		
		
		blake_tab0=new Blake_tab0(tabFolder, tabpage0);
		blake_tab1=new Blake_tab1(tabFolder, tabpage1);
		blake_tab3=new Blake_tab3(tabFolder, tabpage3); 
		
		blake_tab0.message3.addSelectionListener(new SelectionAdapter(){  
			public void widgetSelected(SelectionEvent e){			
					long v16[]=new long[16];
					for(int i=0;i<8;i++) {
						v16[i]=IV224[i]&0xffffffffL;
					}
					for(int i=0; i<4;i++) {
						v16[i+8]=((long)(BLAKE224.Algorithm.state.salt32[i]^c32[i]))& 0xffffffffL;
					}
					v16[12]=((long)(BLAKE224.Algorithm.state.t32[0] ^ c32[4]) & 0xffffffffL);
					v16[13]=((long)(BLAKE224.Algorithm.state.t32[0] ^ c32[5]) & 0xffffffffL);
					v16[14]=((long)(BLAKE224.Algorithm.state.t32[1] ^ c32[6]) & 0xffffffffL);
					v16[15]=((long)(BLAKE224.Algorithm.state.t32[1] ^ c32[7]) & 0xffffffffL);
					
					blake_tab1.load(v16, textInput.getText().getBytes());
//					tabItem1.setControl(blake_tab0.message3);
					tabpage0.setVisible(false);
					tabpage1.setVisible(true);
					tabpage1.layout();
			}
			});
					
			blake_tab1.sigma_button.addSelectionListener(new SelectionAdapter(){  
						public void widgetSelected(SelectionEvent e){
							blake_tab2=new Blake_tab2(tabFolder, tabpage2);
							tabpage0.setVisible(false);
							tabpage1.setVisible(false);
							tabpage2.setVisible(true);
							tabpage2.layout();
							}
				        public void widgetDefaultSelected(SelectionEvent e) {  	      
				        }  
			});
					
			blake_tab1.SaltButton.addSelectionListener(new SelectionAdapter(){  
						public void widgetSelected(SelectionEvent e){
							if(blake_tab1.round_num>=14){
							tabItem3.setText("Hash output");
							blake_tab3.load(blake_tab1.v16_output, textHashOutput.getText());
							for(int i=0; i<4; i++){
								blake_tab3.s4_value[i].setText("0x"+ Integer.toHexString(BLAKE224.Algorithm.state.salt32[i]));
							}
							blake_tab3.load_v16();
							tabpage0.setVisible(false);
							tabpage1.setVisible(false);
							tabpage2.setVisible(false);
							tabpage3.setVisible(true);
							tabpage3.layout();
								}
							}
				        public void widgetDefaultSelected(SelectionEvent e) {  	      
				        }  
		}); 

        Group Hashinput = new Group(compositeMain, SWT.NONE);
		Hashinput.setBounds(10, 70, 400, 650);
		Hashinput.setLayout(new GridLayout(1, false));
		Hashinput.setText("Hash Input");
		
		Group grpHashfunction = new Group(Hashinput, SWT.NONE);
		grpHashfunction.setLayout(new GridLayout(1, false));
		grpHashfunction.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, false, false, 1, 1));
		grpHashfunction.setText("Select a hash function");
		
		comboHash = new Combo(grpHashfunction, SWT.READ_ONLY);
		comboHash.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				if (!textInput.getText().isEmpty()) {
					hashInputValueHex = computeHash(comboHash.getText(), textInput.getText(), null, textHashInput, Hashpage);
					blake_tab0.create_m(BLAKE224,textInput.getText(), textOutput.getText());
					}

				if (!textOutput.getText().isEmpty()) {
					hashOutputValueHex = computeHash(comboHash.getText(), textInput.getText(), textOutput.getText(), textHashOutput, Hashpage);
					blake_tab0.create_m(BLAKE224, textInput.getText(), textOutput.getText());
					}


			}
		});
		comboHash.setItems(new String[] {
						"ECHO (224 bits)", "ECHO (256 bits)", "ECHO (384 bits)", "ECHO (512 bits)", //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
						"JH (224 bits)", "JH (256 bits)", "JH (384 bits)", "JH (512 bits)",
						"BLAKE (224 bits)", "BLAKE (256 bits)", "BLAKE (384 bits)", "BLAKE (512 bits)",
						"SHA-2 (256 bits)", "SHA-2 (512 bits)", "SHA-3 (224 bits)", "SHA-3 (256 bits)", "SHA-3 (384 bits)", "SHA-3 (512 bits)", "SKEIN-256 (256 bits)", "SKEIN-512 (512 bits)", "SKEIN-1024 (1024 bits)", "SM3 (256 bits)", "RIPEMD-160 (160 bits)", "TIGER (192 bits)", "GOST3411 (256 bits)", "WHIRLPOOL (512 bits)" }); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$ //$NON-NLS-6$ //$NON-NLS-7$ //$NON-NLS-8$ //$NON-NLS-9$ //$NON-NLS-10$ //$NON-NLS-11$ //$NON-NLS-12$ //$NON-NLS-13$ //$NON-NLS-14$
		comboHash.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
		comboHash.select(0);

		Group grpTypeHash = new Group(Hashinput, SWT.NONE);
		grpTypeHash.setLayout(new GridLayout(3, false));
		grpTypeHash.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, false, 1, 1));
		grpTypeHash.setText(Messages.HashingView_3);

		btnHexadezimal = new Button(grpTypeHash, SWT.RADIO);
		btnHexadezimal.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				String hash = null;
				if (!textInput.getText().isEmpty()) {
					hash = hashInputValueHex.toUpperCase().replaceAll(".{2}", "$0 "); //$NON-NLS-1$ //$NON-NLS-2$
					textHashInput.setText(hash);
				}

				if (!textOutput.getText().isEmpty()) {
					hash = hashOutputValueHex.toUpperCase().replaceAll(".{2}", "$0 "); //$NON-NLS-1$ //$NON-NLS-2$
					textHashOutput.setText(hash);
				}
			}
		});
		btnHexadezimal.setSelection(true);
		btnHexadezimal.setLayoutData(new GridData(SWT.CENTER, SWT.FILL, true, true, 1, 1));
		btnHexadezimal.setText(Messages.HashingView_4);

		btnDezimal = new Button(grpTypeHash, SWT.RADIO);
		btnDezimal.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				String hash = null;
				if (!textInput.getText().isEmpty()) {
					hash = hexToDecimal(hashInputValueHex);
					hash = hash.replaceAll(".{3}", "$0 "); //$NON-NLS-1$ //$NON-NLS-2$
					textHashInput.setText(hash);
				}

				if (!textOutput.getText().isEmpty()) {
					hash = hexToDecimal(hashOutputValueHex);
					hash = hash.replaceAll(".{3}", "$0 "); //$NON-NLS-1$ //$NON-NLS-2$
					textHashOutput.setText(hash);
				}
			}
		});
		btnDezimal.setLayoutData(new GridData(SWT.CENTER, SWT.FILL, true, true, 1, 1));
		btnDezimal.setText(Messages.HashingView_5);

		btnBinary = new Button(grpTypeHash, SWT.RADIO);
		btnBinary.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				String hash = null;
				if (!textInput.getText().isEmpty()) {
					hash = hexToBinary(hashInputValueHex);
					hash = hash.replaceAll(".{8}", "$0#"); //$NON-NLS-1$ //$NON-NLS-2$
					textHashInput.setText(hash);
				}

				if (!textOutput.getText().isEmpty()) {
					hash = hexToBinary(hashOutputValueHex);
					hash = hash.replaceAll(".{8}", "$0#"); //$NON-NLS-1$ //$NON-NLS-2$
					textHashOutput.setText(hash);
				}

			}
		});
		btnBinary.setLayoutData(new GridData(SWT.CENTER, SWT.FILL, true, true, 1, 1));
		btnBinary.setText(Messages.HashingView_6);


		Group grpInput = new Group(Hashinput, SWT.NONE);
		grpInput.setLayout(new GridLayout(1, false));
		grpInput.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, true, 1, 18));
		grpInput.setText("Input String");

		textInput = new Text(grpInput, SWT.BORDER | SWT.V_SCROLL | SWT.MULTI);
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
					hashInputValueHex = computeHash(comboHash.getText(), textInput.getText(), null, textHashInput, Hashpage);
					hashOutputValueHex = computeHash(comboHash.getText(), textInput.getText(), textOutput.getText(), textHashOutput, Hashpage);
					blake_tab0.create_m(BLAKE224, textInput.getText(), textOutput.getText());
				} else {
					textHashInput.setText(""); //$NON-NLS-1$
				}

			}
		});
		GridData gd_textInput = new GridData(SWT.FILL, SWT.FILL, true, true, 1, 2);
		gd_textInput.heightHint = 90;
		textInput.setLayoutData(gd_textInput);


		Group grpOutput = new Group(Hashinput, SWT.NONE);
		grpOutput.setLayout(new GridLayout(1, false));
		grpOutput.setLayoutData(new GridData(SWT.FILL, SWT.BOTTOM, true, false, 1, 1));
		grpOutput.setText("Salt");

		textOutput = new Text(grpOutput, SWT.BORDER | SWT.V_SCROLL | SWT.MULTI);
		textOutput.addFocusListener(new FocusAdapter() {
			@Override
			public void focusLost(FocusEvent e) {
				textOutput.setSelection(0, 0);
			}
		});
		textOutput.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.stateMask == SWT.CTRL && e.keyCode == 'a') {
					textOutput.selectAll();
				}
			}
		});
		textOutput.addModifyListener(new ModifyListener() {
			@Override
			public void modifyText(ModifyEvent e) {
				if (!textOutput.getText().isEmpty()) {
					hashOutputValueHex = computeHash(comboHash.getText(), textInput.getText(), textOutput.getText(), textHashOutput, Hashpage);
					blake_tab0.create_m(BLAKE224, textInput.getText(), textOutput.getText());
				} else {
					textHashOutput.setText(""); //$NON-NLS-1$
				}

				if (!textInput.getText().isEmpty() && !textOutput.getText().isEmpty()) {

				} else {
					textDifference.setText(""); //$NON-NLS-1$
				}
			}
		});
		GridData gd_textOutput = new GridData(SWT.FILL, SWT.UP, true, true, 1, 1);
		gd_textOutput.heightHint = 90;
		textOutput.setLayoutData(gd_textOutput);
		
		
		
		Group grpHashInput = new Group(compositeMain, SWT.NONE);
		grpHashInput.setBounds(10, 730, 400, 60);
		grpHashInput.setLayout(new GridLayout(1, false));
		grpHashInput.setText(Messages.HashingView_10);

		textHashInput = new Text(grpHashInput, SWT.BORDER | SWT.READ_ONLY);
		textHashInput.setFont(SWTResourceManager.getFont("Courier New", 9, SWT.NORMAL)); //$NON-NLS-1$
		textHashInput.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.stateMask == SWT.CTRL && e.keyCode == 'a') {
					textHashInput.selectAll();
				}
			}
		});
		textHashInput.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));

		Group grpHashOutput = new Group(compositeMain, SWT.NONE);
		grpHashOutput.setBounds(10, 800, 1300, 60);
		grpHashOutput.setLayout(new GridLayout(4, false));
		grpHashOutput.setText(Messages.HashingView_8);

		textHashOutput = new Text(grpHashOutput, SWT.BORDER | SWT.READ_ONLY);
		textHashOutput.setFont(SWTResourceManager.getFont("Courier New", 9, SWT.NORMAL)); //$NON-NLS-1$
		textHashOutput.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.stateMask == SWT.CTRL && e.keyCode == 'a') {
					textHashOutput.selectAll();
				}
			}
		});
		textHashOutput.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));

		
		scrolledComposite.setContent(compositeMain);
		
		scrolledComposite.setMinSize(new Point(1600, 830));						

	}

	private String hexToDecimal(String hex) {
		StringBuilder sb = new StringBuilder();
		String[] a = hex.toUpperCase().split("(?<=\\G..)"); //$NON-NLS-1$

		for (String s : a) {
			sb.append(String.format("%3s", (new BigInteger(s, 16)).toString()).replace(' ', '0')); //$NON-NLS-1$
		}

		return sb.toString();
	}

	private String hexToBinary(String hex) {
		String result = new BigInteger(hex, 16).toString(2);
		switch (hash) {
		case ECHO224:
			result = String.format("%224s", result).replace(' ', '0'); //$NON-NLS-1$
		case ECHO256:
			result = String.format("%256s", result).replace(' ', '0'); //$NON-NLS-1$
		case ECHO384:
			result = String.format("%384s", result).replace(' ', '0'); //$NON-NLS-1$
		case ECHO512:
			result = String.format("%512s", result).replace(' ', '0'); //$NON-NLS-1$
			break;
		case JH224:
			result = String.format("%224s", result).replace(' ', '0'); //$NON-NLS-1$
		case JH256:
			result = String.format("%256s", result).replace(' ', '0'); //$NON-NLS-1$
		case JH384:
			result = String.format("%384s", result).replace(' ', '0'); //$NON-NLS-1$
		case JH512:
			result = String.format("%512s", result).replace(' ', '0'); //$NON-NLS-1$
			break;
		case BLAKE224:
			result = String.format("%224s", result).replace(' ', '0'); //$NON-NLS-1$
		case BLAKE256:
			result = String.format("%256s", result).replace(' ', '0'); //$NON-NLS-1$
		case BLAKE384:
			result = String.format("%384s", result).replace(' ', '0'); //$NON-NLS-1$
		case BLAKE512:
			result = String.format("%512s", result).replace(' ', '0'); //$NON-NLS-1$
			break;
		case RIPEMD160:
			result = String.format("%160s", result).replace(' ', '0'); //$NON-NLS-1$
			break;
		case TIGER:
			result = String.format("%192s", result).replace(' ', '0'); //$NON-NLS-1$
			break;
		case SHA3_224:
			result = String.format("%224s", result).replace(' ', '0'); //$NON-NLS-1$
			break;
		case SHA256:
		case SHA3_256:
		case SKEIN_256:
		case GOST3411:
		case SM3:
			result = String.format("%256s", result).replace(' ', '0'); //$NON-NLS-1$
			break;
		case SHA3_384:
			result = String.format("%384s", result).replace(' ', '0'); //$NON-NLS-1$
			break;
		case SHA512:
		case SHA3_512:
		case SKEIN_512:
		case WHIRLPOOL:
			result = String.format("%512s", result).replace(' ', '0'); //$NON-NLS-1$
			break;
		case SKEIN_1024:
			result = String.format("%1024s", result).replace(' ', '0'); //$NON-NLS-1$
			break;

		default:
			break;
		}

		return result;
	}

	@Override
	public void setFocus() {
		textOutput.setFocus();
	}

	public void resetView() {
		styledTextDescription.setText(Messages.HashingView_0 + Messages.HashingView_1);
		styledTextDescription.setStyleRange(header);

		comboHash.select(0);
		btnHexadezimal.setSelection(true);
		btnDezimal.setSelection(false);
		btnBinary.setSelection(false);

		textInput.setText(""); //$NON-NLS-1$
		textHashInput.setText(""); //$NON-NLS-1$
		textOutput.setText(""); //$NON-NLS-1$
		textHashOutput.setText(""); //$NON-NLS-1$
		textDifference.setText(""); //$NON-NLS-1$
		Hashpage.setUrl("");

	}
	
	private String computeHash(String hashName, String inputText, String saltText, Text hashText, Browser hashpage) {
		hash = hash.getName(hashName);
		byte[] digest = null;
		switch (hash) {
		case ECHO224:
			ECHOAction echo224 = new ECHOAction();
			digest=echo224.run(224, inputText);
			hashpage.setUrl("file:///C:/workspace1/org.jcryptool.visual.sha3candidates/nl/en/help/content/ECHOTutorial.html");
			break;
		case ECHO256:
			ECHOAction echo256 = new ECHOAction();
			digest=echo256.run(256, inputText);
			hashpage.setUrl("file:///C:/workspace1/org.jcryptool.visual.sha3candidates/nl/en/help/content/ECHOTutorial.html");
			break;

		case ECHO384:
			ECHOAction echo384 = new ECHOAction();
			digest=echo384.run(384, inputText);
			hashpage.setUrl("file:///C:/workspace1/org.jcryptool.visual.sha3candidates/nl/en/help/content/ECHOTutorial.html");
			break;

		case ECHO512:
			ECHOAction echo512= new ECHOAction();
			digest=echo512.run(512, inputText);
			hashpage.setUrl("file:///C:/workspace1/org.jcryptool.visual.sha3candidates/nl/en/help/content/ECHOTutorial.html");
			break;
		case JH224:
			JHAction JH224 = new JHAction();
			digest=JH224.run(224, inputText);
			hashpage.setUrl("file:///C:/workspace1/git/crypto/org.jcryptool.crypto.modern.sha3/nl/en/help/content/JHTutorial.html");
			break;
		case JH256:
			JHAction JH256 = new JHAction();
			digest=JH256.run(256, inputText);
			hashpage.setUrl("file:///C:/workspace1/git/crypto/org.jcryptool.crypto.modern.sha3/nl/en/help/content/JHTutorial.html");
			break;

		case JH384:
			JHAction JH384 = new JHAction();
			digest=JH384.run(384, inputText);
			hashpage.setUrl("file:///C:/workspace1/git/crypto/org.jcryptool.crypto.modern.sha3/nl/en/help/content/JHTutorial.html");
			break;

		case JH512:
			JHAction JH512= new JHAction();
			digest=JH512.run(512, inputText);
			hashpage.setUrl("file:///C:/workspace1/git/crypto/org.jcryptool.crypto.modern.sha3/nl/en/help/content/JHTutorial.html");
			break;
		case BLAKE224:
			BLAKE224= new Blake_Action();
			if(saltText==null)	{
				digest=BLAKE224.run(224, inputText);
			}	else if(saltText.length()!=32){
				String salt_extend=saltText;
				for(int i=0; i<32-saltText.length();i++){
					salt_extend="0"+salt_extend;
				}
				digest=BLAKE224.run(224, inputText, salt_extend);
			}
			break;
		case BLAKE256:
			Blake_Action BLAKE256 = new Blake_Action();
			if(saltText==null)	{
				digest=BLAKE256.run(256, inputText);
			}	else if(saltText.length()!=32){
				digest=BLAKE256.run(256, inputText);
				hashText.setText("salt must be a 32 character string!!!");
				return "salt must be a 32 character string!!!";
			}	else {
				digest=BLAKE256.run(256, inputText, saltText);
			}
			hashpage.setUrl("file:///C:/workspace1/org.jcryptool.visual.sha3candidates/nl/en/help/content/ECHOTutorial.html");

			break;

		case BLAKE384:
			Blake_Action BLAKE384 = new Blake_Action();
			digest=BLAKE384.run(384, inputText, saltText);
			hashpage.setUrl("file:///C:/workspace1/org.jcryptool.visual.sha3candidates/nl/en/help/content/ECHOTutorial.html");
			break;

		case BLAKE512:
			Blake_Action BLAKE512= new Blake_Action();
			digest=BLAKE512.run(512, inputText, saltText);
			hashpage.setUrl("file:///C:/workspace1/org.jcryptool.visual.sha3candidates/nl/en/help/content/ECHOTutorial.html");
			break;

		case SHA256:
			SHA256Digest sha256 = new SHA256Digest();
			sha256.update(inputText.getBytes(), 0, inputText.getBytes().length);
			digest = new byte[sha256.getDigestSize()];
			sha256.doFinal(digest, 0);

			break;
		case SHA512:
			SHA512Digest sha512 = new SHA512Digest();
			sha512.update(inputText.getBytes(), 0, inputText.getBytes().length);
			digest = new byte[sha512.getDigestSize()];
			sha512.doFinal(digest, 0);

			break;
		case SHA3_224:
			SHA3.Digest224 sha3_224 = new SHA3.Digest224();
			sha3_224.update(inputText.getBytes(), 0, inputText.getBytes().length);
			digest = new byte[sha3_224.getDigestLength()];
			digest = sha3_224.digest();
			hashpage.setUrl("file:///C:/workspace1/org.jcryptool.visual.sha3candidates/nl/en/help/content/ECHOTutorial.html");

			break;
		case SHA3_256:
			SHA3.Digest256 sha3_256 = new SHA3.Digest256();
			sha3_256.update(inputText.getBytes(), 0, inputText.getBytes().length);
			digest = new byte[sha3_256.getDigestLength()];
			digest = sha3_256.digest();
			hashpage.setUrl("file:///C:/workspace1/org.jcryptool.visual.sha3candidates/nl/en/help/content/ECHOTutorial.html");

			break;
		case SHA3_384:
			SHA3.Digest384 sha3_384 = new SHA3.Digest384();
			sha3_384.update(inputText.getBytes(), 0, inputText.getBytes().length);
			digest = new byte[sha3_384.getDigestLength()];
			digest = sha3_384.digest();
			hashpage.setUrl("file:///C:/workspace1/org.jcryptool.visual.sha3candidates/nl/en/help/content/ECHOTutorial.html");

			break;
		case SHA3_512:
			SHA3.Digest512 sha3_512 = new SHA3.Digest512();
			sha3_512.update(inputText.getBytes(), 0, inputText.getBytes().length);
			digest = new byte[sha3_512.getDigestLength()];
			digest = sha3_512.digest();
			hashpage.setUrl("file:///C:/workspace1/org.jcryptool.visual.sha3candidates/nl/en/help/content/ECHOTutorial.html");

			break;
		case SKEIN_256:
			Skein.Digest_256_256 skein_256 = new Skein.Digest_256_256();
			skein_256.update(inputText.getBytes(), 0, inputText.getBytes().length);
			digest = new byte[skein_256.getDigestLength()];
			digest = skein_256.digest();
			hashpage.setUrl("file:///C:/workspace1/git/crypto/org.jcryptool.crypto.modern.sha3/nl/en/help/content/SkeinTutorial.html");

			break;
		case SKEIN_512:
			Skein.Digest_512_512 skein_512 = new Skein.Digest_512_512();
			skein_512.update(inputText.getBytes(), 0, inputText.getBytes().length);
			digest = new byte[skein_512.getDigestLength()];
			digest = skein_512.digest();
			hashpage.setUrl("file:///C:/workspace1/git/crypto/org.jcryptool.crypto.modern.sha3/nl/en/help/content/SkeinTutorial.html");

			break;
		case SKEIN_1024:
			Skein.Digest_1024_1024 skein_1024 = new Skein.Digest_1024_1024();
			skein_1024.update(inputText.getBytes(), 0, inputText.getBytes().length);
			digest = new byte[skein_1024.getDigestLength()];
			digest = skein_1024.digest();
			hashpage.setUrl("file:///C:/workspace1/git/crypto/org.jcryptool.crypto.modern.sha3/nl/en/help/content/SkeinTutorial.html");

			break;
		case RIPEMD160:
			RIPEMD160Digest ripemd160 = new RIPEMD160Digest();
			ripemd160.update(inputText.getBytes(), 0, inputText.getBytes().length);
			digest = new byte[ripemd160.getDigestSize()];
			ripemd160.doFinal(digest, 0);

			break;
		case SM3:
			SM3Digest sm3 = new SM3Digest();
			sm3.update(inputText.getBytes(), 0, inputText.getBytes().length);
			digest = new byte[sm3.getDigestSize()];
			sm3.doFinal(digest, 0);

			break;
		case TIGER:
			TigerDigest tiger = new TigerDigest();
			tiger.update(inputText.getBytes(), 0, inputText.getBytes().length);
			digest = new byte[tiger.getDigestSize()];
			tiger.doFinal(digest, 0);

			break;
		case GOST3411:
			GOST3411Digest gost3411 = new GOST3411Digest();
			gost3411.update(inputText.getBytes(), 0, inputText.getBytes().length);
			digest = new byte[gost3411.getDigestSize()];
			gost3411.doFinal(digest, 0);

			break;
		case WHIRLPOOL:
			WhirlpoolDigest whirlpool = new WhirlpoolDigest();
			whirlpool.update(inputText.getBytes(), 0, inputText.getBytes().length);
			digest = new byte[whirlpool.getDigestSize()];
			whirlpool.doFinal(digest, 0);

			break;
		default:
			break;
		}
		
		String hashHexValue = new String(Hex.encode(digest));
		if (btnHexadezimal.getSelection()) {
			String hashValue = hashHexValue.toUpperCase().replaceAll(".{2}", "$0 "); //$NON-NLS-1$ //$NON-NLS-2$
			hashText.setText(hashValue);
		} else if (btnDezimal.getSelection()) {
			String hashValue = hexToDecimal(hashHexValue);
			hashValue = hashValue.replaceAll(".{3}", "$0 "); //$NON-NLS-1$ //$NON-NLS-2$
			hashText.setText(hashValue);
		} else if (btnBinary.getSelection()) {
			String hashValue = hexToBinary(hashHexValue);
			hashValue = hashValue.replaceAll(".{8}", "$0#"); //$NON-NLS-1$ //$NON-NLS-2$
			hashText.setText(hashValue);
		}

		return hashHexValue;
	}


	
}
