package org.jcryptool.visual.sha3candidates.algorithms.BLAKE;

import org.jcryptool.visual.sha3candidates.algorithms.BLAKE.Blake_Action;
import org.jcryptool.visual.sha3candidates.views.Messages;

import static org.jcryptool.visual.sha3candidates.algorithms.BLAKE.Blake_Algorithm.IV224;
import static org.jcryptool.visual.sha3candidates.algorithms.BLAKE.Blake_Algorithm.c32;

import java.nio.ByteBuffer;
import java.util.Arrays;

import org.bouncycastle.util.encoders.Hex;
import org.eclipse.jface.dialogs.MessageDialog;
import org.eclipse.jface.resource.ImageDescriptor;
import org.eclipse.swt.SWT;
import org.eclipse.swt.browser.Browser;
import org.eclipse.swt.custom.StyledText;
import org.eclipse.swt.events.MouseAdapter;
import org.eclipse.swt.events.MouseEvent;
import org.eclipse.swt.events.MouseListener;
import org.eclipse.swt.events.FocusAdapter;
import org.eclipse.swt.events.FocusEvent;
import org.eclipse.swt.events.KeyAdapter;
import org.eclipse.swt.events.KeyEvent;
import org.eclipse.swt.events.PaintEvent;
import org.eclipse.swt.events.PaintListener;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.graphics.GC;
import org.eclipse.swt.graphics.Image;
import org.eclipse.swt.graphics.ImageData;
import org.eclipse.swt.graphics.Rectangle;
import org.eclipse.swt.layout.FillLayout;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Canvas;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Group;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.TabFolder;
import org.eclipse.swt.widgets.TabItem;
import org.eclipse.swt.widgets.Table;
import org.eclipse.swt.widgets.TableColumn;
import org.eclipse.swt.widgets.TableItem;
import org.eclipse.swt.widgets.Text;
import org.eclipse.wb.swt.SWTResourceManager;
import org.jcryptool.visual.sha3candidates.algorithms.HashFunction;

public class Blake_tab1 {
	
	public short sigma[][] = {
            {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
            { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
            { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
            {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
            {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
            {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
            { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
            { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
            {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
            { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 }, 
            {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
            { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
            { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
            {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
            {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
            {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
            { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
            { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
            {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
            { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 }  
          };

	public Table table;
	public Table table1;
	public Browser Hashpage;
	public String hashName="BLAKE224", inputText=null, saltText=null;
	public HashFunction hash=null;
	public byte[] digest=null;
	public TableItem item[]; 
	public TabFolder tabFolder;
	public Group m_panel; 
	public Label m16_index[]=new Label[16];	
	public Text m16_value[]=new Text[16];
	public Group s_panel; 
	public Label s4_index[]=new Label[4];;	
	public Text s4_value[]=new Text[4];;
	public TabItem tabItem;
	public Group tabpage;
	public Group h_panel;
	public Label h8_index[]=new Label[8];;
	public Text h8_value[]=new Text[8];;
	public Group c_panel;
	public Label c16_index[]=new Label[16];;	
	public Text c16_value[]=new Text[16];
	public Group t_panel;
	public Label t2_index[]=new Label[2];
	public Text t2_value[]=new Text[2];
	public GC gc;
	public Blake_Action BLAKE224;
	public GridLayout grid;
	public Group v0_panel;
	public Group v_panel;
	public Label v_label;
	public Canvas v_canvas;
	public Image v_image;
	public Label v16_index[]=new Label[16];
	public long v16_initial[]=new long[16];
	public long v16_input[]=new long[16];
	public long v16_output[]=new long[16];
	public StyledText tutorial_text;
	public Button message1, message2, message3;
	public Group g0_panel[]=new Group[8];
	public Label g0_index[][]=new Label[8][4];
	public Text g0_value[][]=new Text[8][4];
	public Group g1_panel[]=new Group[8];
	public Label g1_index[][]=new Label[8][4];
	public Text g1_value[][]=new Text[8][4];
	public Button calc[]=new Button[20];
	public int round_num=0;
	public byte datablock[]=new byte[64];
	public long m_block[]=new long[16];
	public long m1, c1, m2, c2;
	public Button sigma_button;
	public Label sigma_panel;
	public Button SaltButton;
	public long v16[]=new long[16];
	
	public Blake_tab1(TabFolder tabFolder_input, Group tabpage_input){
		tabFolder=tabFolder_input;
		tabpage=tabpage_input;
		create_tab0();
	}
	
	public void load(long v16[], byte[] input){
		v16_initial=v16;
		v16_input=v16;
		for(int i=0; i<input.length;i++){
			datablock[i]=input[i];
		}
	}
	
	public void create_tab0(){	
		message1=new Button(tabpage, SWT.BORDER);
		message1.setForeground(SWTResourceManager.getColor(SWT.COLOR_LINK_FOREGROUND));
		message1.setBackground(SWTResourceManager.getColor(SWT.COLOR_LINK_FOREGROUND));
		message2=new Button(tabpage, SWT.BORDER);
		message2.setForeground(SWTResourceManager.getColor(SWT.COLOR_LINK_FOREGROUND));
		message2.setBackground(SWTResourceManager.getColor(SWT.COLOR_LINK_FOREGROUND));
		message3=new Button(tabpage, SWT.BORDER);
		message3.setForeground(SWTResourceManager.getColor(SWT.COLOR_LINK_FOREGROUND));
		message3.setBackground(SWTResourceManager.getColor(SWT.COLOR_LINK_FOREGROUND));

		sigma_button=new Button(tabpage, SWT.BORDER);
		sigma_panel=new Label(tabpage, SWT.BORDER);
		
		
		

//		Hashpage = new Browser(tabpage, SWT.BORDER);
//		Hashpage.setBounds(800, 130, 300, 300);
//		Hashpage.setUrl("file:///C:/workspace1/org.jcryptool.visual.sha3candidates/nl/en/help/content/ECHOTutorial.html");
		
		gc = new GC(tabpage);
		gc.setLineWidth(4);
		tabpage.addPaintListener(new PaintListener(){
	        public void paintControl(PaintEvent e){
	        	e.gc.setLineWidth(4);
	            e.gc.drawLine(0,325,20,325);
	            e.gc.drawLine(20,325,20,100);
	            e.gc.drawLine(20,100,120,100);

	        }
	    });
		
		int width=150, height=20;

		for(int i=0; i<8; i++){
			g0_panel[0] = new Group(tabpage, SWT.NONE| SWT.SHADOW_IN|SWT.SHADOW_OUT);
			g0_panel[0].setBounds(60, 10+50*i, 610, 50);
			g0_index[i][0] = new Label(g0_panel[0], SWT.NONE);
			g0_index[i][0].setBounds(5+width*0, 5, width, height);
			g0_index[i][0].setAlignment(SWT.CENTER);
			g0_value[i][0] = new Text(g0_panel[0], SWT.BORDER|SWT.CENTER);
			g0_value[i][0].setBounds(5+width*0, 5+height, width, height);
			g0_index[i][1] = new Label(g0_panel[0], SWT.NONE);
			g0_index[i][1].setBounds(5+width*1, 5, width, height);
			g0_index[i][1].setAlignment(SWT.CENTER);
			g0_value[i][1] = new Text(g0_panel[0], SWT.BORDER|SWT.CENTER);
			g0_value[i][1].setBounds(5+width*1, 5+height, width, height);
			g0_index[i][2] = new Label(g0_panel[0], SWT.NONE);
			g0_index[i][2].setBounds(5+width*2, 5, width, height);
			g0_index[i][2].setAlignment(SWT.CENTER);
			g0_value[i][2] = new Text(g0_panel[0], SWT.BORDER|SWT.CENTER);
			g0_value[i][2].setBounds(5+width*2, 5+height, width, height);
			g0_index[i][3] = new Label(g0_panel[0], SWT.NONE);
			g0_index[i][3].setBounds(5+width*3, 5, width, height);
			g0_index[i][3].setAlignment(SWT.CENTER);
			g0_value[i][3] = new Text(g0_panel[0], SWT.BORDER|SWT.CENTER);
			g0_value[i][3].setBounds(5+width*3, 5+height, width, height);	
		}

		
		g0_index[0][0].setText("v0");
		g0_index[0][1].setText("v4");
		g0_index[0][2].setText("v8");
		g0_index[0][3].setText("v12");
		g0_index[1][0].setText("v1");
		g0_index[1][1].setText("v5");
		g0_index[1][2].setText("v9");
		g0_index[1][3].setText("v13");
		g0_index[2][0].setText("v2");
		g0_index[2][1].setText("v6");
		g0_index[2][2].setText("v10");
		g0_index[2][3].setText("v14");
		g0_index[3][0].setText("v3");
		g0_index[3][1].setText("v7");
		g0_index[3][2].setText("v11");
		g0_index[3][3].setText("v15");
		g0_index[4][0].setText("v0");
		g0_index[4][1].setText("v5");
		g0_index[4][2].setText("v10");
		g0_index[4][3].setText("v15");
		g0_index[5][0].setText("v1");
		g0_index[5][1].setText("v6");
		g0_index[5][2].setText("v11");
		g0_index[5][3].setText("v12");
		g0_index[6][0].setText("v2");
		g0_index[6][1].setText("v7");
		g0_index[6][2].setText("v8");
		g0_index[6][3].setText("v13");
		g0_index[7][0].setText("v3");
		g0_index[7][1].setText("v4");
		g0_index[7][2].setText("v9");
		g0_index[7][3].setText("v14");
		
		g0_value[0][0].setText("0x"+v16_input[0]);
		g0_value[0][1].setText("0x"+v16_input[4]);
		g0_value[0][2].setText("0x"+v16_input[8]);
		g0_value[0][3].setText("0x"+v16_input[12]);
		g0_value[1][0].setText("0x"+v16_input[1]);
		g0_value[1][1].setText("0x"+v16_input[5]);
		g0_value[1][2].setText("0x"+v16_input[9]);
		g0_value[1][3].setText("0x"+v16_input[13]);
		g0_value[2][0].setText("0x"+v16_input[2]);
		g0_value[2][1].setText("0x"+v16_input[6]);
		g0_value[2][2].setText("0x"+v16_input[10]);
		g0_value[2][3].setText("0x"+v16_input[14]);
		g0_value[3][0].setText("0x"+v16_input[3]);
		g0_value[3][1].setText("0x"+v16_input[7]);
		g0_value[3][2].setText("0x"+v16_input[11]);
		g0_value[3][3].setText("0x"+v16_input[15]);
		g0_value[4][0].setText("0x"+v16_input[0]);
		g0_value[4][1].setText("0x"+v16_input[5]);
		g0_value[4][2].setText("0x"+v16_input[10]);
		g0_value[4][3].setText("0x"+v16_input[15]);
		g0_value[5][0].setText("0x"+v16_input[1]);
		g0_value[5][1].setText("0x"+v16_input[6]);
		g0_value[5][2].setText("0x"+v16_input[11]);
		g0_value[5][3].setText("0x"+v16_input[12]);
		g0_value[6][0].setText("0x"+v16_input[2]);
		g0_value[6][1].setText("0x"+v16_input[7]);
		g0_value[6][2].setText("0x"+v16_input[8]);
		g0_value[6][3].setText("0x"+v16_input[13]);
		g0_value[7][0].setText("0x"+v16_input[3]);
		g0_value[7][1].setText("0x"+v16_input[4]);
		g0_value[7][2].setText("0x"+v16_input[9]);
		g0_value[7][3].setText("0x"+v16_input[14]);
		
		m_block=compress32(datablock);
		
		
		for(int i=0; i<8; i++){
			g1_panel[0] = new Group(tabpage, SWT.NONE| SWT.SHADOW_IN|SWT.SHADOW_OUT);
			g1_panel[0].setBounds(750, 10+50*i, 610, 50);
			g1_index[i][0] = new Label(g1_panel[0], SWT.NONE);
			g1_index[i][0].setBounds(5+width*0, 5, width, height);
			g1_index[i][0].setAlignment(SWT.CENTER);
			g1_value[i][0] = new Text(g1_panel[0], SWT.BORDER|SWT.CENTER);
			g1_value[i][0].setBounds(5+width*0, 5+height, width, height);
			g1_index[i][1] = new Label(g1_panel[0], SWT.NONE);
			g1_index[i][1].setBounds(5+width*1, 5, width, height);
			g1_index[i][1].setAlignment(SWT.CENTER);
			g1_value[i][1] = new Text(g1_panel[0], SWT.BORDER|SWT.CENTER);
			g1_value[i][1].setBounds(5+width*1, 5+height, width, height);
			g1_index[i][2] = new Label(g1_panel[0], SWT.NONE);
			g1_index[i][2].setBounds(5+width*2, 5, width, height);
			g1_index[i][2].setAlignment(SWT.CENTER);
			g1_value[i][2] = new Text(g1_panel[0], SWT.BORDER|SWT.CENTER);
			g1_value[i][2].setBounds(5+width*2, 5+height, width, height);
			g1_index[i][3] = new Label(g1_panel[0], SWT.NONE);
			g1_index[i][3].setBounds(5+width*3, 5, width, height);
			g1_index[i][3].setAlignment(SWT.CENTER);
			g1_value[i][3] = new Text(g1_panel[0], SWT.BORDER|SWT.CENTER);
			g1_value[i][3].setBounds(5+width*3, 5+height, width, height);	
		}
		g1_index[0][0].setText("v0");
		g1_index[0][1].setText("v4");
		g1_index[0][2].setText("v8");
		g1_index[0][3].setText("v12");
		g1_index[1][0].setText("v1");
		g1_index[1][1].setText("v5");
		g1_index[1][2].setText("v9");
		g1_index[1][3].setText("v13");
		g1_index[2][0].setText("v2");
		g1_index[2][1].setText("v6");
		g1_index[2][2].setText("v10");
		g1_index[2][3].setText("v14");
		g1_index[3][0].setText("v3");
		g1_index[3][1].setText("v7");
		g1_index[3][2].setText("v11");
		g1_index[3][3].setText("v15");
		g1_index[4][0].setText("v0");
		g1_index[4][1].setText("v5");
		g1_index[4][2].setText("v10");
		g1_index[4][3].setText("v15");
		g1_index[5][0].setText("v1");
		g1_index[5][1].setText("v6");
		g1_index[5][2].setText("v11");
		g1_index[5][3].setText("v12");
		g1_index[6][0].setText("v2");
		g1_index[6][1].setText("v7");
		g1_index[6][2].setText("v8");
		g1_index[6][3].setText("v13");
		g1_index[7][0].setText("v3");
		g1_index[7][1].setText("v4");
		g1_index[7][2].setText("v9");
		g1_index[7][3].setText("v14");
		
		
		
		message2.addSelectionListener(new SelectionAdapter(){  
			public void widgetSelected(SelectionEvent e){
				gc.drawLine(1000, 415, 1000, 500);
				gc.drawLine(995, 495, 1000, 500);
				gc.drawLine(1005, 495, 1000, 500);
				message3.setText("Double click to continue");
				message3.setBounds(780, 680, 620, 30);
			}
		});

		Button MessageButton = new Button(tabpage, SWT.NONE);
		MessageButton.setText("Compress");
		MessageButton.setBounds(20, 440, 80, 50);
		MessageButton.addSelectionListener(new SelectionAdapter(){  
			public void widgetSelected(SelectionEvent e){
				v16_input=v16_initial;
				///a////
				gc.setLineWidth(8);
				gc.drawLine(135,410,135,460);
				gc.drawLine(155,480,650,480);
				gc.drawLine(690, 480, 835, 480);
				gc.drawLine(835,480,835,410);
				gc.drawLine(830,425,835,410);
				gc.drawLine(840,425,835,410);
				////b////
				gc.drawLine(285,410,285,550);
				gc.drawLine(285,550,340,550);
				gc.drawLine(380,550,455,550);
				gc.drawLine(515,550,965,550);
				gc.drawLine(985,530,985,500);
				gc.drawLine(985,460,985,410);
				gc.drawLine(990,425,985,410);
				gc.drawLine(980,425,985,410);
				////c////
				gc.drawLine(435,410,435,620);
				gc.drawLine(435,620,1115,620);
				gc.drawLine(1135,600,1135,410);
				gc.drawLine(1130,425,1135,410);
				gc.drawLine(1140,425,1135,410);
				////d/////
				gc.drawLine(585,410,585, 425);//90);
				gc.drawLine(585,465,585,690);
				gc.drawLine(585,690,640,690);
				gc.drawLine(700, 690,815, 690);
				gc.drawLine(855, 690, 945, 690);
				gc.drawLine(1005, 690, 1285,690);
				gc.drawLine(1285,690, 1285,410);
				gc.drawLine(1280,425,1285,410);
				gc.drawLine(1290,425,1285,410);
				
				gc.setLineWidth(4);
				
				////ba////
				gc.drawLine(285,550,135,550);
				gc.drawLine(135,550,135,500);
				gc.drawLine(130,520,135,500);
				gc.drawLine(140,520,135,500);
				calc[0]=new Button(tabpage, SWT.NONE|SWT.ON_TOP);
				calc[0].setAlignment(SWT.CENTER);
				calc[0].setBounds(115, 460, 40, 40);
				calc[0].setFont(SWTResourceManager.getFont("Segoe UI", 18, SWT.BOLD));
				calc[0].setText("+");
				////oa////
				gc.drawLine(210,720,210,480);
				gc.drawLine(205,500,210,480);
				gc.drawLine(215,500,210,480);
				calc[12]=new Button(tabpage, SWT.NONE|SWT.ON_TOP);
				calc[12].setAlignment(SWT.CENTER);
				calc[12].setBounds(50, 720, 140, 40);
				calc[12].setText("m");
				calc[1]=new Button(tabpage, SWT.NONE|SWT.ON_TOP);
				calc[1].setBounds(190, 720, 40, 40);
				calc[1].setAlignment(SWT.CENTER);
				calc[1].setFont(SWTResourceManager.getFont("Segoe UI", 18, SWT.BOLD));
				calc[1].setText("+");
				calc[13]=new Button(tabpage, SWT.NONE|SWT.ON_TOP);
				calc[13].setAlignment(SWT.CENTER);
				calc[13].setBounds(230, 720, 140, 40);
				calc[13].setText("c");
				/////cb/////
				gc.drawLine(435,620,360,620);
				gc.drawLine(360,620,360,570);
				gc.drawLine(350,590,360,570);
				gc.drawLine(370,590,360,570);
				calc[2]=new Button(tabpage, SWT.NONE|SWT.ON_TOP);
				calc[2].setBounds(340, 530, 40,40);
				calc[2].setAlignment(SWT.CENTER);
				calc[2].setFont(SWTResourceManager.getFont("Segoe UI", 10, SWT.BOLD));
				calc[2].setText("XOR");
				////ad/////
				gc.drawLine(485, 480, 485, 445);
				gc.drawLine(485, 445, 565, 445);
				gc.drawLine(545, 435, 565, 445);
				gc.drawLine(545, 455, 565, 445);
				calc[3]=new Button(tabpage, SWT.NONE|SWT.ON_TOP);
				calc[3].setBounds(565, 425, 40, 40);
				calc[3].setAlignment(SWT.CENTER);
				calc[3].setFont(SWTResourceManager.getFont("Segoe UI", 10, SWT.BOLD));
				calc[3].setText("XOR");
				
				calc[8]=new Button(tabpage, SWT.NONE|SWT.ON_TOP);
				calc[8].setAlignment(SWT.CENTER);
				calc[8].setBounds(455, 530, 60, 40);
				calc[8].setFont(SWTResourceManager.getFont("Segoe UI", 10, SWT.BOLD));
				calc[8].setText(">>>12");
				
				////ba////
				gc.drawLine(670,550,670,500);
				gc.drawLine(660,520,670,500);
				gc.drawLine(680,520,670,500);
				calc[4]=new Button(tabpage, SWT.NONE|SWT.ON_TOP);
				calc[4].setBounds(650, 460, 40, 40);
				calc[4].setAlignment(SWT.CENTER);
				calc[4].setFont(SWTResourceManager.getFont("Segoe UI", 18, SWT.BOLD));
				calc[4].setText("+");
				calc[9]=new Button(tabpage, SWT.NONE|SWT.ON_TOP);
				calc[9].setAlignment(SWT.CENTER);
				calc[9].setBounds(640, 670, 60, 40);
				calc[9].setFont(SWTResourceManager.getFont("Segoe UI", 10, SWT.BOLD));
				calc[9].setText(">>>16");
				
				
				////oa////
				gc.drawLine(750,720,750,480);
				gc.drawLine(740,500,750,480);
				gc.drawLine(760,500,750,480);
				calc[14]=new Button(tabpage, SWT.NONE|SWT.ON_TOP);
				calc[14].setAlignment(SWT.CENTER);
				calc[14].setBounds(590, 720, 140, 40);
				calc[14].setText("m");
				calc[5]=new Button(tabpage, SWT.NONE|SWT.ON_TOP);
				calc[5].setAlignment(SWT.CENTER);
				calc[5].setBounds(730, 720, 40, 40);
				calc[5].setAlignment(SWT.CENTER);
				calc[5].setFont(SWTResourceManager.getFont("Segoe UI", 18, SWT.BOLD));
				calc[5].setText("+");
				calc[15]=new Button(tabpage, SWT.NONE|SWT.ON_TOP);
				calc[15].setAlignment(SWT.CENTER);
				calc[15].setBounds(770, 720, 140, 40);
				calc[15].setText("c");
				////ad///
				gc.drawLine(835,480,835,670);
				gc.drawLine(830,650,835,670);
				gc.drawLine(840,650,835,670);
				calc[6]=new Button(tabpage, SWT.NONE|SWT.ON_TOP);
				calc[6].setBounds(815, 670, 40, 40);
				calc[6].setAlignment(SWT.CENTER);
				calc[6].setFont(SWTResourceManager.getFont("Segoe UI", 10, SWT.BOLD));
				calc[6].setText("XOR");
				
				calc[10]=new Button(tabpage, SWT.NONE|SWT.ON_TOP);
				calc[10].setAlignment(SWT.CENTER);
				calc[10].setBounds(945, 460, 60, 40);
				calc[10].setFont(SWTResourceManager.getFont("Segoe UI", 10, SWT.BOLD));
				calc[10].setText(">>>7");
				
				calc[7]=new Button(tabpage, SWT.NONE|SWT.ON_TOP);
				calc[7].setAlignment(SWT.CENTER);
				calc[7].setBounds(965, 530, 40, 40);
				calc[7].setFont(SWTResourceManager.getFont("Segoe UI", 10, SWT.BOLD));
				calc[7].setText("XOR");
								
				calc[11]=new Button(tabpage, SWT.NONE|SWT.ON_TOP);
				calc[11].setAlignment(SWT.CENTER);
				calc[11].setBounds(945, 670, 60, 40);
				calc[11].setFont(SWTResourceManager.getFont("Segoe UI", 10, SWT.BOLD));
				calc[11].setText(">>>8");
				
				calc[16]=new Button(tabpage, SWT.NONE|SWT.ON_TOP);
				calc[16].setAlignment(SWT.CENTER);
				calc[16].setBounds(1115,600,40,40);
				calc[16].setFont(SWTResourceManager.getFont("Segoe UI", 18, SWT.BOLD));
				calc[16].setText("+");
				
				////cb////
				gc.drawLine(1135,550,1005,550);
				gc.drawLine(1025,560,1005,550);
				gc.drawLine(1025,540,1005,550);
				
				////dc///
				gc.drawLine(1135,690,1135,640);
				gc.drawLine(1125,660,1135,640);
				gc.drawLine(1145,660,1135,640);
				
				for(int i=0; i<8; i++){
					gc.setLineWidth(4);
					gc.setLineStyle(SWT.LINE_DASHDOT);
					gc.drawLine(670, 40+50*i, 750, 40+50*i);
					gc.drawLine(740, 40+50*i-10, 750, 40+50*i);
					gc.drawLine(740, 40+50*i+10, 750, 40+50*i);
					
				}
				gc.setLineStyle(SWT.LINE_SOLID);
				
			}
			
	        public void widgetDefaultSelected(SelectionEvent e) {  	      
	        }  
	    });  
		
		sigma_button.setBounds(20, 620, 150, 50);
		sigma_button.setText("sigma matrix");
		
		SaltButton = new Button(tabpage, SWT.NONE);
		SaltButton.setText("Round "+round_num);
		SaltButton.setBounds(20, 520, 100, 50);
		SaltButton.addSelectionListener(new SelectionAdapter(){  
			public void widgetSelected(SelectionEvent e){
	            
	            gc.drawLine(70,  570,  70, 620);
	            gc.drawLine(25, 670, 25, 740);
	            gc.drawLine(25, 740, 50, 740);
	            
				g0_value[0][0].setText("0x"+v16_input[0]);
				g0_value[0][1].setText("0x"+v16_input[4]);
				g0_value[0][2].setText("0x"+v16_input[8]);
				g0_value[0][3].setText("0x"+v16_input[12]);
				g0_value[1][0].setText("0x"+v16_input[1]);
				g0_value[1][1].setText("0x"+v16_input[5]);
				g0_value[1][2].setText("0x"+v16_input[9]);
				g0_value[1][3].setText("0x"+v16_input[13]);
				g0_value[2][0].setText("0x"+v16_input[2]);
				g0_value[2][1].setText("0x"+v16_input[6]);
				g0_value[2][2].setText("0x"+v16_input[10]);
				g0_value[2][3].setText("0x"+v16_input[14]);
				g0_value[3][0].setText("0x"+v16_input[3]);
				g0_value[3][1].setText("0x"+v16_input[7]);
				g0_value[3][2].setText("0x"+v16_input[11]);
				g0_value[3][3].setText("0x"+v16_input[15]);
				g0_value[4][0].setText("0x"+v16_input[0]);
				g0_value[4][1].setText("0x"+v16_input[5]);
				g0_value[4][2].setText("0x"+v16_input[10]);
				g0_value[4][3].setText("0x"+v16_input[15]);
				g0_value[5][0].setText("0x"+v16_input[1]);
				g0_value[5][1].setText("0x"+v16_input[6]);
				g0_value[5][2].setText("0x"+v16_input[11]);
				g0_value[5][3].setText("0x"+v16_input[12]);
				g0_value[6][0].setText("0x"+v16_input[2]);
				g0_value[6][1].setText("0x"+v16_input[7]);
				g0_value[6][2].setText("0x"+v16_input[8]);
				g0_value[6][3].setText("0x"+v16_input[13]);
				g0_value[7][0].setText("0x"+v16_input[3]);
				g0_value[7][1].setText("0x"+v16_input[4]);
				g0_value[7][2].setText("0x"+v16_input[9]);
				g0_value[7][3].setText("0x"+v16_input[14]);
				
				v16_output=round(m_block, v16_initial, (short)round_num);
				round_num++;
				SaltButton.setText("Round "+round_num);
				calc[12].setText("0x"+m1);
				calc[13].setText("0x"+c1);
				calc[14].setText("0x"+m2);
				calc[15].setText("0x"+c2);
						
				
				g1_value[0][0].setText("0x"+v16_output[0]);
				g1_value[0][1].setText("0x"+v16_output[4]);
				g1_value[0][2].setText("0x"+v16_output[8]);
				g1_value[0][3].setText("0x"+v16_output[12]);
				g1_value[1][0].setText("0x"+v16_output[1]);
				g1_value[1][1].setText("0x"+v16_output[5]);
				g1_value[1][2].setText("0x"+v16_output[9]);
				g1_value[1][3].setText("0x"+v16_output[13]);
				g1_value[2][0].setText("0x"+v16_output[2]);
				g1_value[2][1].setText("0x"+v16_output[6]);
				g1_value[2][2].setText("0x"+v16_output[10]);
				g1_value[2][3].setText("0x"+v16_output[14]);
				g1_value[3][0].setText("0x"+v16_output[3]);
				g1_value[3][1].setText("0x"+v16_output[7]);
				g1_value[3][2].setText("0x"+v16_output[11]);
				g1_value[3][3].setText("0x"+v16_output[15]);
				g1_value[4][0].setText("0x"+v16_output[0]);
				g1_value[4][1].setText("0x"+v16_output[5]);
				g1_value[4][2].setText("0x"+v16_output[10]);
				g1_value[4][3].setText("0x"+v16_output[15]);
				g1_value[5][0].setText("0x"+v16_output[1]);
				g1_value[5][1].setText("0x"+v16_output[6]);
				g1_value[5][2].setText("0x"+v16_output[11]);
				g1_value[5][3].setText("0x"+v16_output[12]);
				g1_value[6][0].setText("0x"+v16_output[2]);
				g1_value[6][1].setText("0x"+v16_output[7]);
				g1_value[6][2].setText("0x"+v16_output[8]);
				g1_value[6][3].setText("0x"+v16_output[13]);
				g1_value[7][0].setText("0x"+v16_output[3]);
				g1_value[7][1].setText("0x"+v16_output[4]);
				g1_value[7][2].setText("0x"+v16_output[9]);
				g1_value[7][3].setText("0x"+v16_output[14]);
				
				v16_input=v16_output;
	        }
	        public void widgetDefaultSelected(SelectionEvent e) {  	      
	        }  
	    });  
        
		
				
		

}
	
	public void create_2X1_matrix(Group t_panel, String name, Label t2_index[], Text t2_value[], int height, int width){
		for(int k=0; k<2; k++){
			t2_index[k] = new Label(t_panel, SWT.NONE);
			t2_index[k].setBounds(5+width*k, 5, width, height);
			t2_index[k].setAlignment(SWT.CENTER);
			t2_index[k].setText(name+k);
			t2_value[k] = new Text(t_panel, SWT.BORDER|SWT.CENTER);
			t2_value[k].setBounds(5+width*k, 5+height, width, height);
		}
	}
	
	public void create_4X1_matrix(Group s_panel, String name, Label s4_index[], Text s4_value[], int height, int width){
		for(int k=0; k<4; k++){
			s4_index[k] = new Label(s_panel, SWT.NONE);
			s4_index[k].setBounds(5+width*k, 5, width, height);
			s4_index[k].setText(name+k);
			s4_index[k].setAlignment(SWT.CENTER);
			s4_value[k] = new Text(s_panel, SWT.BORDER|SWT.CENTER);
			s4_value[k].setBounds(5+width*k, 5+height, width, height);
		}
	}
	
	public void create_4X2_matrix(Group h_panel, String name, Label h8_index[], Text h8_value[], int height, int width){
		for(int k=0; k<4; k++){
			h8_index[k] = new Label(h_panel, SWT.NONE);
			h8_index[k].setBounds(5+width*k, 5, width, height);
			h8_index[k].setAlignment(SWT.CENTER);
			h8_index[k].setText(name+k);
			h8_value[k] = new Text(h_panel, SWT.BORDER|SWT.CENTER);
			h8_value[k].setBounds(5+width*k, 5+height, width, height);
		}
		for(int k=4; k<8; k++){
			h8_index[k] = new Label(h_panel, SWT.NONE);
			h8_index[k].setBounds(5+width*(k-4), 5+height*2, width, height);
			h8_index[k].setAlignment(SWT.CENTER);
			h8_index[k].setText(name+k);
			h8_value[k] = new Text(h_panel, SWT.BORDER|SWT.CENTER);
			h8_value[k].setBounds(5+width*(k-4), 5+height*3, width, height);
		}

	}
	public void create_4X4_matrix(Group c_panel, String name, Label c16_index[], Text c16_value[], int height, int width){
		for(int i=0; i<4; i++){
			c16_index[i] = new Label(c_panel, SWT.NONE);
			c16_index[i].setBounds(5+width*i, 5, width, height);
			c16_index[i].setText(name+i);
			c16_index[i].setAlignment(SWT.CENTER);
		}
		for(int i=0; i<4; i++){
			c16_value[i] = new Text(c_panel, SWT.BORDER | SWT.CENTER);
			c16_value[i].setBounds(5+width*i, 5+height, width, height);
		}
		for(int i=4; i<8; i++){
			c16_index[i] = new Label(c_panel, SWT.NONE);
			c16_index[i].setBounds(5+width*(i-4), 5+2*height, width, height);
			c16_index[i].setText(name+i);
			c16_index[i].setAlignment(SWT.CENTER);
		}
		for(int i=4; i<8; i++){
			c16_value[i] = new Text(c_panel, SWT.BORDER|SWT.CENTER);
			c16_value[i].setBounds(5+width*(i-4), 5+3*height, width, height);
		}
		for(int i=8; i<12; i++){
			c16_index[i] = new Label(c_panel, SWT.NONE);
			c16_index[i].setBounds(5+width*(i-8), 5+4*height, width, height);
			c16_index[i].setText(name+i);
			c16_index[i].setAlignment(SWT.CENTER);
		}
		for(int i=8; i<12; i++){
			c16_value[i] = new Text(c_panel, SWT.BORDER|SWT.CENTER);
			c16_value[i].setBounds(5+width*(i-8), 5+5*height, width, height);
		}
		for(int i=12; i<16; i++){
			c16_index[i] = new Label(c_panel, SWT.NONE);
			c16_index[i].setBounds(5+width*(i-12), 5+6*height, width, height);
			c16_index[i].setText(name+i);
			c16_index[i].setAlignment(SWT.CENTER);
		}
		for(int i=12; i<16; i++){
			c16_value[i] = new Text(c_panel, SWT.BORDER|SWT.CENTER);
			c16_value[i].setBounds(5+width*(i-12), 5+7*height, width, height);
		}
	}
	
	public void create_m(Blake_Action BLAKE, String inputText, String saltText){
		BLAKE224=BLAKE;
	}
	
	public long[] compress32(byte[] datablock){
		
	        long m[] = new long[16];
	        m[0] = U8TO32_BE(Arrays.copyOfRange(datablock,0,4));
	        m[1] = U8TO32_BE(Arrays.copyOfRange(datablock,4,8));
	        m[2] = U8TO32_BE(Arrays.copyOfRange(datablock,8,12));
	        m[3] = U8TO32_BE(Arrays.copyOfRange(datablock,12,16));
	        m[4] = U8TO32_BE(Arrays.copyOfRange(datablock,16,20));
	        m[5] = U8TO32_BE(Arrays.copyOfRange(datablock,20,24));
	        m[6] = U8TO32_BE(Arrays.copyOfRange(datablock,24,28));
	        m[7] = U8TO32_BE(Arrays.copyOfRange(datablock,28,32));
	        m[8] = U8TO32_BE(Arrays.copyOfRange(datablock,32,36));
	        m[9] = U8TO32_BE(Arrays.copyOfRange(datablock,36,40));
	        m[10] = U8TO32_BE(Arrays.copyOfRange(datablock,40,44));
	        m[11] = U8TO32_BE(Arrays.copyOfRange(datablock,44,48));
	        m[12] = U8TO32_BE(Arrays.copyOfRange(datablock,48,52));
	        m[13] = U8TO32_BE(Arrays.copyOfRange(datablock,52,56));
	        m[14] = U8TO32_BE(Arrays.copyOfRange(datablock,56,60));
	        m[15] = U8TO32_BE(Arrays.copyOfRange(datablock,60,64));
	        return m;
	}
	        /* initialization */
	       
	        /*  do 14 rounds */
	          /* column step */
	public long[] round(long m[], long[] v16_input, short round_num){
	    	
		v16_output = G32(v16_input, m, round_num, 0, 4, 8,12, 0);
	    v16_output = G32(v16_input, m, round_num, 1, 5, 9,13, 1);
	    v16_output = G32(v16_input, m, round_num, 2, 6,10,14, 2);
	    v16_output = G32(v16_input, m, round_num, 3, 7,11,15, 3);    

	          /* diagonal step */
	    v16_output = G32(v16_input, m, round_num, 0, 5,10,15, 4);
	    v16_output = G32(v16_input, m, round_num, 1, 6,11,12, 5);
	    v16_output = G32(v16_input, m, round_num, 2, 7, 8,13, 6);
	    v16_output = G32(v16_input, m, round_num, 3, 4, 9,14, 7);
	    
	    return v16_output;
	    }
	
	  private long[] G32(long v[], long m[], short round, int a, int b, int c, int d, int i){ 
		  m1=m[sigma[round][2*i]];
		  c1=c32[sigma[round][2*i+1]];
		  m2=m[sigma[round][2*i+1]];
		  c2=c32[sigma[round][2*i]]	;  
		  v[a] = ADD32(v[a],v[b])+XOR32(m[sigma[round][2*i]], c32[sigma[round][2*i+1]]);
		  v[d] = ROT32(XOR32(v[d],v[a]),16);
		  v[c] = ADD32(v[c],v[d]);
		  v[b] = ROT32(XOR32(v[b],v[c]),12);
		  v[a] = ADD32(v[a],v[b])+XOR32(m[sigma[round][2*i+1]], c32[sigma[round][2*i]]);
		  v[d] = ROT32(XOR32(v[d],v[a]), 8);
		  v[c] = ADD32(v[c],v[d]);
		  v[b] = ROT32(XOR32(v[b],v[c]), 7); 
		  return v;
	  }
	  
	    private long ROT32(long x, long n){
	        return (((x<<(32-n))|(x>>n))& 0xffffffffL);
	    }
	    
	    private long ADD32(long x, long y){
	        return ((x + y) & 0xffffffffL);
	    }
	    
	    private long XOR32(long x, long y){
	        return ((x ^ y) & 0xffffffffL);
	    }
	 
	 public static int U8TO32_BE(byte[] p){
			int q = java.nio.ByteBuffer.wrap(p).getInt();
			       return q; }	 
	 
	    
}