package org.jcryptool.visual.sha3candidates.views;

import java.io.File;  
import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.util.ArrayList;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
import org.eclipse.swt.widgets.Table;
import org.eclipse.swt.widgets.TableColumn;
import org.eclipse.swt.widgets.TableItem;


public class HashingView2_origin extends ViewPart {

	/**
	 * The ID of the view as specified by the extension.
	 */
	public static final String ID = "org.jcryptool.visual.sha3candidates.views.HashingView"; //$NON-NLS-1$
	private static final int OUTPUT_SEPERATOR = 144;

	private org.jcryptool.visual.sha3candidates.algorithms.HashFunction hash = org.jcryptool.visual.sha3candidates.algorithms.HashFunction.ECHO224;
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
	private Blake_Action BLAKE224;	
	private TabFolder tabFolder;

	/**
	 * The constructor.
	 */
	public HashingView2_origin() {
	}

	@Override
	public void createPartControl(Composite parent) {

		ScrolledComposite scrolledComposite = new ScrolledComposite(parent, SWT.BORDER | SWT.H_SCROLL | SWT.V_SCROLL);
		scrolledComposite.setExpandHorizontal(true);
		scrolledComposite.setExpandVertical(true);
		scrolledComposite.setBounds(10, 10, 639, 410);
		Composite compositeMain = new Composite(scrolledComposite, SWT.NONE);
////////		compositeMain.setLayout(new GridLayout(2, false));
		compositeMain.setLayout(new GridLayout(4, false));
		compositeMain.setBounds(10, 10, 600, 400);
		
		styledTextDescription = new StyledText(compositeMain, SWT.BORDER | SWT.READ_ONLY | SWT.WRAP);
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
		GridData gd_styledTextDescription = new GridData(SWT.FILL, SWT.FILL, true, false, 4, 1);
		gd_styledTextDescription.widthHint = 300;
		gd_styledTextDescription.heightHint = 60;
		styledTextDescription.setLayoutData(gd_styledTextDescription);
		styledTextDescription.setText(Messages.HashingView_0 + Messages.HashingView_1);

		header = new StyleRange();
		header.start = 0;
		header.length = Messages.HashingView_0.length();
		header.fontStyle = SWT.BOLD;
		styledTextDescription.setStyleRange(header);

		Menu menu_1 = new Menu(styledTextDescription);
		styledTextDescription.setMenu(menu_1);

		MenuItem mntmCopy_1 = new MenuItem(menu_1, SWT.NONE);
		mntmCopy_1.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				styledTextDescription.copy();
			}
		});
		mntmCopy_1.setText(Messages.HashingView_mntmCopy_text);

		MenuItem menuItem_1 = new MenuItem(menu_1, SWT.SEPARATOR);

		MenuItem mntmSelectAll_1 = new MenuItem(menu_1, SWT.NONE);
		mntmSelectAll_1.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				styledTextDescription.selectAll();
			}
		});
		mntmSelectAll_1.setText(Messages.HashingView_mntmSelectAll_text);

		Group Hashinput = new Group(compositeMain, SWT.NONE);
////////grpHashfunction.setLayout(new GridLayout(1, false));
		Hashinput.setLayout(new GridLayout(1, false));
////////grpHashfunction.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
		Hashinput.setLayoutData(new GridData(SWT.LEFT, SWT.FILL, false, true, 1, 10));
		Hashinput.setText("Hash Input");
		
		Group grpHashfunction = new Group(Hashinput, SWT.NONE);
////////		grpHashfunction.setLayout(new GridLayout(1, false));
		grpHashfunction.setLayout(new GridLayout(1, false));
////////		grpHashfunction.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
		grpHashfunction.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, false, false, 1, 1));
		grpHashfunction.setText(Messages.HashingView_2);
		
		Group grpHashalgorithm = new Group(compositeMain, SWT.NONE);
		grpHashalgorithm.setLayout(new GridLayout(1, false));
		grpHashalgorithm.setLayoutData(new GridData(SWT.RIGHT, SWT.FILL, true, true, 3, 10));
		grpHashalgorithm.setText("Hash Algorithm");
		
		tabFolder = new TabFolder(grpHashalgorithm, SWT.NONE); 
        tabFolder.setLayout(new GridLayout(10, true));  
        tabFolder.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, true, 1, 1));  
        
		TabItem tabItem1 = new TabItem(tabFolder, SWT.NONE);
		tabItem1.setText("属性标签1");
		TabItem tabItem2 = new TabItem(tabFolder, SWT.NONE);
		tabItem2.setText("属性标签2");
		
		Group tabpage1 = new Group(tabFolder, SWT.NONE);
		tabpage1.setLayout(new GridLayout(1, true));  
		tabItem1.setControl(tabpage1);
		Hashpage = new Browser(tabpage1, SWT.NONE);
		Hashpage.setLayout(new FillLayout());
		Hashpage.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, true, 1, 1));
		Hashpage.setUrl(page);
		

		Group tabpage2 = new Group(tabFolder, SWT.NONE);
		tabpage2.setLayout(new GridLayout(10, true));  
		tabItem2.setControl(tabpage2);

		table1 = new Table(tabpage2, SWT.BORDER | SWT.FULL_SELECTION);
		table1.setLayoutData(new GridData(SWT.LEFT, SWT.UP, true, true, 1, 1));
		table1.setHeaderVisible(true);
		table1.setLinesVisible(true);
		TableColumn tc1[] = new TableColumn[2];
		tc1[0]=new TableColumn(table1, SWT.CENTER);
		tc1[0].setWidth(40);
		tc1[0].setResizable(true);
		tc1[0].setText("hhhhhh");
		tc1[1] = new TableColumn(table1, SWT.CENTER);
		tc1[1].setWidth(100);
		tc1[1].setResizable(true);
		tc1[1].setText("valueeeeeeeeeeee");
		TableItem item[]= new TableItem[8];
		for (int col = 0; col < 8 ; col++) {
			item[col]= new TableItem(table1, SWT.NONE);
		}
		
		
		table = new Table(tabpage2, SWT.BORDER | SWT.FULL_SELECTION);
		table.setHeaderVisible(true);
		table.setLinesVisible(true); 
		table.setLayoutData(new GridData(SWT.LEFT, SWT.UP, true, true, 1, 1));
		TableColumn tc[] = new TableColumn[2];
		tc[0]=new TableColumn(table, SWT.CENTER);
		tc[0].setWidth(40);
		tc[0].setResizable(true);
		tc[0].setText("h");
		tc[1] = new TableColumn(table, SWT.CENTER);
		tc[1].setWidth(100);
		tc[1].setResizable(true);
		tc[1].setText("value");
		TableItem item1[]= new TableItem[8];
		for (int col = 0; col < 8 ; col++) {
			item1[col]= new TableItem(table, SWT.NONE);
		}
		
		
		
		
		comboHash = new Combo(grpHashfunction, SWT.READ_ONLY);
		comboHash.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				if (!textInput.getText().isEmpty()) {
					hashInputValueHex = computeHash(comboHash.getText(), textInput.getText(), textHashInput, Hashpage, item);
				}

				if (!textOutput.getText().isEmpty()) {
					hashOutputValueHex = computeHash(comboHash.getText(), textOutput.getText(), textHashOutput, Hashpage, item);
				}

				if (!textInput.getText().isEmpty() && !textOutput.getText().isEmpty()) {
					computeDifference();
				} else {
					textDifference.setText(""); //$NON-NLS-1$
				}
			}
		});
		comboHash
				.setItems(new String[] {
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
		grpInput.setLayoutData(new GridData(SWT.LEFT, SWT.FILL, true, true, 4, 2));
		grpInput.setText(Messages.HashingView_7);

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
					hashInputValueHex = computeHash(comboHash.getText(), textInput.getText(), textHashInput, Hashpage, item);
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
		GridData gd_textInput = new GridData(SWT.FILL, SWT.FILL, true, true, 1, 2);
		gd_textInput.heightHint = 90;
		textInput.setLayoutData(gd_textInput);


		Group grpOutput = new Group(Hashinput, SWT.NONE);
		grpOutput.setLayout(new GridLayout(1, false));
		grpOutput.setLayoutData(new GridData(SWT.LEFT, SWT.FILL, true, true, 4, 2));
		grpOutput.setText(Messages.HashingView_9);

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
					hashOutputValueHex = computeHash(comboHash.getText(), textOutput.getText(), textHashOutput, Hashpage, item);
				} else {
					textHashOutput.setText(""); //$NON-NLS-1$
				}

				if (!textInput.getText().isEmpty() && !textOutput.getText().isEmpty()) {
					computeDifference();
				} else {
					textDifference.setText(""); //$NON-NLS-1$
				}
			}
		});
		GridData gd_textOutput = new GridData(SWT.FILL, SWT.FILL, true, true, 1, 2);
		gd_textOutput.heightHint = 90;
		textOutput.setLayoutData(gd_textOutput);

		Group grpHashInput = new Group(compositeMain, SWT.NONE);
		grpHashInput.setLayout(new GridLayout(1, false));
		grpHashInput.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, false, false, 4, 1));
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
		grpHashOutput.setLayout(new GridLayout(4, false));
		grpHashOutput.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, false, false, 4, 1));
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

		Group grpUnterschied = new Group(compositeMain, SWT.NONE);
		grpUnterschied.setLayout(new GridLayout(4, false));
		grpUnterschied.setLayoutData(new GridData(SWT.FILL, SWT.FILL, false, true, 4, 1));
		grpUnterschied.setText(Messages.HashingView_11);

		textDifference = new StyledText(grpUnterschied, SWT.BORDER | SWT.FULL_SELECTION | SWT.READ_ONLY | SWT.WRAP
				| SWT.V_SCROLL);
		textDifference.addFocusListener(new FocusAdapter() {
			@Override
			public void focusLost(FocusEvent e) {
				textDifference.setSelection(0, 0);
			}
		});
		textDifference.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.stateMask == SWT.CTRL && e.keyCode == 'a') {
					textDifference.selectAll();
				}
			}
		});
		textDifference.setLayoutData(new GridData(SWT.FILL, SWT.FILL, false, true, 4, 1));

		Menu menu = new Menu(textDifference);
		textDifference.setMenu(menu);

		MenuItem mntmCopy = new MenuItem(menu, SWT.NONE);
		mntmCopy.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				textDifference.copy();
			}
		});
		mntmCopy.setText(Messages.HashingView_mntmCopy_text);

		MenuItem menuItem = new MenuItem(menu, SWT.SEPARATOR);

		MenuItem mntmSelectAll = new MenuItem(menu, SWT.NONE);
		mntmSelectAll.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				textDifference.selectAll();
			}
		});
		mntmSelectAll.setText(Messages.HashingView_mntmSelectAll_text);

		btnUnchanged = new Button(grpUnterschied, SWT.RADIO);
		btnUnchanged.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				computeDifference();
			}
		});
		btnUnchanged.setSelection(true);
		btnUnchanged.setLayoutData(new GridData(SWT.CENTER, SWT.CENTER, true, false, 1, 1));
		btnUnchanged.setText(Messages.HashingView_btnUnchanged_text);

		btnChanged = new Button(grpUnterschied, SWT.RADIO);
		btnChanged.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				computeDifference();
			}
		});
		btnChanged.setLayoutData(new GridData(SWT.CENTER, SWT.CENTER, true, false, 1, 1));
		btnChanged.setText(Messages.HashingView_btnChanged_text);
		textDifference.invokeAction(ST.CUT);
		textDifference.invokeAction(ST.COPY);
		textDifference.invokeAction(ST.PASTE);
		scrolledComposite.setContent(compositeMain);
		
		if (System.getProperty("os.name").compareToIgnoreCase("Windows 10") == 0) {
			scrolledComposite.setMinSize(new Point(1600, 830));						
		} else {
			scrolledComposite.setMinSize(new Point(1000, 630));			
		}

		loadExampleText();
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

		loadExampleText();
	}
	
	private String computeHash(String hashName, String inputText, Text hashText, Browser hashpage, TableItem item[]) {
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
			digest=BLAKE224.run(224, inputText, null);
			hashpage.setUrl("file:///C:/workspace1/org.jcryptool.visual.sha3candidates/nl/en/help/content/ECHOTutorial.html");
			
			for(int i=0; i<item.length;i++){
				item[i].setText(0, "h"+i);
//				item[i].setText(1, "0x"+Integer.toHexString(BLAKE224.e.state.h32[i]));
			}
			
			break;
		case BLAKE256:
			Blake_Action BLAKE256 = new Blake_Action();
			digest=BLAKE256.run(256, inputText, null);
			hashpage.setUrl("file:///C:/workspace1/org.jcryptool.visual.sha3candidates/nl/en/help/content/ECHOTutorial.html");
			break;

		case BLAKE384:
			Blake_Action BLAKE384 = new Blake_Action();
			digest=BLAKE384.run(384, inputText, null);
			hashpage.setUrl("file:///C:/workspace1/org.jcryptool.visual.sha3candidates/nl/en/help/content/ECHOTutorial.html");
			break;

		case BLAKE512:
			Blake_Action BLAKE512= new Blake_Action();
			digest=BLAKE512.run(512, inputText, null);
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
			String hashValueOutput = hashHexValue.toUpperCase().replaceAll(".{2}", "$0 "); //$NON-NLS-1$ //$NON-NLS-2$
			hashText.setText(hashValueOutput);
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

	private void computeDifference() {
		BigInteger input = new BigInteger(hashInputValueHex, 16);
		BigInteger output = new BigInteger(hashOutputValueHex, 16);
		BigInteger zero=new BigInteger("000000", 16);
		String result = input.xor(output).toString(16);
		result = hexToBinary(result);

		if (result.toString().equalsIgnoreCase("0")) { //$NON-NLS-1$
			textDifference.setText((hexToBinary("0").replaceAll(".{8}", "$0#"))); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		} else {
			int count = result.length();
			int zeroBits = result.length() - result.replace("0", "").length(); //$NON-NLS-1$ //$NON-NLS-2$
			int oneBits = result.length() - result.replace("1", "").length(); //$NON-NLS-1$ //$NON-NLS-2$
			double percent = ((double) oneBits / (double) count) * 100;
			ArrayList<int[]> sequence = findUnchanged(result);
			ArrayList<int[]> sequenceChanged = findChanged(result);

			result = result.replaceAll(".{8}", "$0#"); //$NON-NLS-1$ //$NON-NLS-2$

			int lengthPrettyPrint = result.length();
			count = lengthPrettyPrint / OUTPUT_SEPERATOR;

			StringBuilder sb = new StringBuilder(result);

			for (int i = 0; i < count; i++) {
				sb.insert(((OUTPUT_SEPERATOR) * (i + 1) + i), "\n"); //$NON-NLS-1$
			}

			if (hash == HashFunction.RIPEMD160 || hash == HashFunction.TIGER
					|| hash == HashFunction.SHA3_224) {
				sb.insert(sb.length(), "\n"); //$NON-NLS-1$
			}

			char[] bitArray = sb.toString().toCharArray();

			sb.append("\n" + String.format("%1$,.2f", percent) //$NON-NLS-1$ //$NON-NLS-2$
					+ Messages.HashingView_12 + oneBits + Messages.HashingView_13 + (zeroBits + oneBits)
					+ Messages.HashingView_14 + sequence.get(0)[1] + Messages.HashingView_15 + sequence.get(0)[0] + "."); //$NON-NLS-1$

			if (!sequenceChanged.isEmpty()) {
				sb.append(Messages.HashingView_17 + sequenceChanged.get(0)[1] + Messages.HashingView_15
						+ sequenceChanged.get(0)[0] + Messages.HashingView_18 + sequence.size()
						+ Messages.HashingView_21 + sequenceChanged.size() + "."); //$NON-NLS-1$
			}

			textDifference.setText(sb.toString());
			if (btnUnchanged.getSelection()) {
				for (int[] is : sequence) {
					StyleRange sr = new StyleRange();
					sr.start = is[1] + (is[1] / 8) + ((is[1] + (is[1] / 8)) / OUTPUT_SEPERATOR);

					int cr = ((((is[1] + (is[1] / 8) ) % OUTPUT_SEPERATOR) + is[0] ) / OUTPUT_SEPERATOR);
					if ((is[1] + is[0]) % 8 != 0) {
						int seed = ((is[1] % 8) + is[0]) / 8;
						sr.length = is[0] + seed + cr;
					} else {
						int seed = 8 - (is[1] % 8);
						
						if (is[0] <= seed) {
							sr.length = is[0] + cr;
						} else {
							sr.length = is[0] + ((is[0] + seed) / 8) + cr;
						}
					}
					sr.underline = true;
					textDifference.setStyleRange(sr);
				}
			}

			for (int i = 0; i < bitArray.length; i++) {
				if (bitArray[i] == '1') {
					StyleRange bits = new StyleRange();
					bits.start = i;
					bits.length = 1;
					bits.foreground = this.getSite().getShell().getDisplay().getSystemColor(SWT.COLOR_RED);
					textDifference.setStyleRange(bits);
				}
			}

			if (btnChanged.getSelection()) {
				if (btnChanged.getSelection()) {
					for (int[] is : sequenceChanged) {
						StyleRange sr = new StyleRange();						
						sr.start = is[1] + (is[1] / 8) + ((is[1] + (is[1] / 8)) / OUTPUT_SEPERATOR);
						int cr = ((((is[1] + (is[1] / 8) ) % OUTPUT_SEPERATOR) + is[0] ) / OUTPUT_SEPERATOR);
						
						if ((is[1] + is[0]) % 8 != 0) {
							int seed = ((is[1] % 8) + is[0]) / 8;
							sr.length = is[0] + seed + cr;
						} else {
							int seed = 8 - (is[1] % 8);
							
							if (is[0] <= seed) {
								sr.length = is[0] + cr;
							} else {
								sr.length = is[0] + ((is[0] + seed) / 8) + cr;
							}
						}
						sr.underline = true;
						sr.foreground = this.getSite().getShell().getDisplay().getSystemColor(SWT.COLOR_RED);
						textDifference.setStyleRange(sr);
					}
				}
			}
		}
	}

	private ArrayList<int[]> findUnchanged(String s) {
		ArrayList<int[]> result = new ArrayList<>();

		String currentSequence = null;
		String prevSequence = null;

		Matcher m = Pattern.compile("(0+)").matcher(s); //$NON-NLS-1$
		m.find();
		prevSequence = m.group();
		currentSequence = m.group();

		while (m.find()) {
			currentSequence = m.group();
			if (prevSequence.length() < currentSequence.length()) {
				prevSequence = m.group();
			}
		}

		if (prevSequence != null) {
			m = Pattern.compile(prevSequence).matcher(s);
			while (m.find()) {
				int[] tmp = new int[2];
				tmp[0] = m.group().length();
				tmp[1] = m.start();
				result.add(tmp);
			}
		}
		return result;
	}

	private ArrayList<int[]> findChanged(String s) {
		ArrayList<int[]> result = new ArrayList<>();

		String currentSequence = null;
		String prevSequence = null;

		Matcher m = Pattern.compile("(1+)").matcher(s); //$NON-NLS-1$
		if (m.find()) {
			prevSequence = m.group();
			currentSequence = m.group();

			while (m.find()) {
				currentSequence = m.group();
				if (prevSequence.length() < currentSequence.length()) {
					prevSequence = m.group();
				}
			}
		}

		if (prevSequence != null) {
			m = Pattern.compile(prevSequence).matcher(s);
			while (m.find()) {
				int[] tmp = new int[2];
				tmp[0] = m.group().length();
				tmp[1] = m.start();
				result.add(tmp);
			}
		}
		return result;
	}

	private void loadExampleText() {
		try {
			URL url = HashingPlugin.getDefault().getBundle().getEntry("/"); //$NON-NLS-1$
			File template = new File(FileLocator.toFileURL(url).getFile() + "templates" + File.separatorChar //$NON-NLS-1$
					+ Messages.HashingView_16);

			Scanner scanner = new Scanner(template, "UTF-8"); //$NON-NLS-1$
			String fileString = scanner.useDelimiter("\\Z").next(); //$NON-NLS-1$
			scanner.close();

			textInput.setText(fileString);
			textOutput.setText(fileString);

		} catch (IOException e) {
			LogUtil.logError(e);
		}
	}
}
