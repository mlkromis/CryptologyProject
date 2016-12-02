package org.jcryptool.visual.sha3candidates.algorithms.BLAKE;

import org.jcryptool.visual.sha3candidates.algorithms.BLAKE.Blake_Action;
import org.jcryptool.visual.sha3candidates.views.Messages;

import static org.jcryptool.visual.sha3candidates.algorithms.BLAKE.Blake_Algorithm.IV224;
import static org.jcryptool.visual.sha3candidates.algorithms.BLAKE.Blake_Algorithm.c32;
import org.bouncycastle.util.encoders.Hex;
import org.eclipse.jface.dialogs.MessageDialog;
import org.eclipse.swt.SWT;
import org.eclipse.swt.browser.Browser;
import org.eclipse.swt.events.PaintEvent;
import org.eclipse.swt.events.PaintListener;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.graphics.GC;
import org.eclipse.swt.graphics.Rectangle;
import org.eclipse.swt.layout.FillLayout;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
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


public class Blake_tab3 {
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
	public TabItem tabItem1;
	public Group tabpage;
	public Group IV_panel;
	public Label IV8_index[]=new Label[8];;
	public Text IV8_value[]=new Text[8];;
	public Group c_panel;
	public Label c16_index[]=new Label[16];;	
	public Text c16_value[]=new Text[16];;
	public GC gc;
	public Blake_Action BLAKE224;
	public GridLayout grid;
	public TabItem tabItem;
	public Group h_panel;
	public Label h8_index[]=new Label[8];;
	public Text h8_value[]=new Text[8];;
	public Label v16_index[]=new Label[16];
	public Text v16_value[]=new Text[16];
	public long v16_initial[]=new long[16];
	public long v16_input[]=new long[16];
	public long v16_output[]=new long[16];
	public Group g0_panel[]=new Group[8];
	public Label g0_index[][]=new Label[8][4];
	public Text g0_value[][]=new Text[8][4];
	public Group g1_panel[]=new Group[8];
	public Label g1_index[][]=new Label[8][4];
	public Text g1_value[][]=new Text[8][4];
	public Text hash_text;
	public String hash_output="0";
	public Label final_algorithm;
	
	public Blake_tab3(TabFolder tabFolder_input, Group tabpage_input){
		tabFolder=tabFolder_input;
		tabpage=tabpage_input;
		create_tab0();
	}

	
	public void load(long v16[], String output){
		v16_input=v16;
		v16_initial=v16;
		v16_output=v16;
		hash_output=output;
	}
	
	public void create_tab0(){	
		gc = new GC(tabpage);
		gc.setLineWidth(4);
		
		c_panel = new Group(tabpage,SWT.BORDER| SWT.SHADOW_IN|SWT.SHADOW_OUT);
		c_panel.setBounds(60, 420, 620, 180);
		create_4X4_matrix(c_panel, "c", c16_index, c16_value, 20, 150);
		for(int i=0; i<16; i++){
			c16_value[i].setText("0x"+ Integer.toHexString((int)(c32[i]>>5))+ Integer.toHexString((int)(c32[i])));
		}
				
		h_panel = new Group(tabpage, SWT.BORDER|  SWT.SHADOW_IN|SWT.SHADOW_OUT);
		h_panel.setBounds(60, 600, 420, 100);
		create_4X2_matrix(h_panel, "h", h8_index, h8_value, 20, 100);
		for(int i=0; i<8; i++){
			h8_value[i].setText("0x"+ Integer.toHexString(IV224[i]));
		}
		
		s_panel = new Group(tabpage, SWT.BORDER| SWT.SHADOW_IN|SWT.SHADOW_OUT);
		s_panel.setBounds(60, 700, 420, 60);
		create_4X1_matrix(s_panel, "s", s4_index, s4_value, 20, 100);	

		hash_text=new Text(tabpage, SWT.BORDER);
		hash_text.setBounds(760, 500, 620, 180);

		
		final_algorithm=new Label(tabpage, SWT.BORDER);
		final_algorithm.setBounds(780, 100, 620, 3500);
		final_algorithm.setFont(SWTResourceManager.getFont("Segoe UI", 10, SWT.ITALIC));
		final_algorithm.setText("\n\n\nh0 = h0 XOR s0 XOR v0 XOR v8\n"
								+ "h1 = h1 XOR s1 XOR v1 XOR v9\n"
								+ "h2 = h2 XOR s2 XOR v2 XOR v10\n"
								+ "h3 = h3 XOR s3 XOR v3 XOR v11\n"
								+ "h4 = h4 XOR s0 XOR v4 XOR v12\n"
								+ "h5 = h5 XOR s1 XOR v5 XOR v13\n"
								+ "h6 = h6 XOR s2 XOR v6 XOR v14\n"
								+ "h7   h7 XOR s3 XOR v7 XOR v15\n\n"
								+ "h1~h7 are outputs");
		final_algorithm.setAlignment(SWT.CENTER);
		
		Button MessageButton = new Button(tabpage, SWT.NONE);
		MessageButton.setText("Click to continue");
		MessageButton.setBounds(780, 10, 620, 50);
		MessageButton.addSelectionListener(new SelectionAdapter(){  
			public void widgetSelected(SelectionEvent e){
				gc.drawLine(660,110,780,110);
				
				gc.drawLine(680,500,720,500);
				gc.drawLine(720,500,720,130);
				gc.drawLine(720,130,780,130);
				
				gc.drawLine(480,660,740,660);
				gc.drawLine(740,660,740,150);
				gc.drawLine(740,150,780,150);
								
				gc.drawLine(480,750,760,750);
	            gc.drawLine(760,750,760,170);
	            gc.drawLine(760,170,780,170);
	            
				gc.drawLine(1090,400,1090,500); 
				
				hash_text.setText(hash_output);
			}
	        public void widgetDefaultSelected(SelectionEvent e) {  	      
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
	}

	public void load_v16(){		
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
}