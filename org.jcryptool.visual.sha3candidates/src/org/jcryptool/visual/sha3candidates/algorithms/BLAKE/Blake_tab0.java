package org.jcryptool.visual.sha3candidates.algorithms.BLAKE;

import org.jcryptool.visual.sha3candidates.algorithms.BLAKE.Blake_Action;
import org.jcryptool.visual.sha3candidates.views.Messages;

import static org.jcryptool.visual.sha3candidates.algorithms.BLAKE.Blake_Algorithm.IV224;
import static org.jcryptool.visual.sha3candidates.algorithms.BLAKE.Blake_Algorithm.c32;


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


public class Blake_tab0 {
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
	public Text v16_value[]=new Text[16];
	public StyledText tutorial_text;
	public Button message1, message2, message3;
	public Button MessageButton, SaltButton;
	public Blake_tab0(TabFolder tabFolder_input, Group tabpage_input){
		tabFolder=tabFolder_input;
		tabpage=tabpage_input;
		create_tab0();
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


//		Hashpage = new Browser(tabpage, SWT.BORDER);
//		Hashpage.setBounds(800, 130, 300, 300);
//		Hashpage.setUrl("file:///C:/workspace1/org.jcryptool.visual.sha3candidates/nl/en/help/content/ECHOTutorial.html");
		
		gc = new GC(tabpage);
		gc.setLineWidth(4);
		tabpage.addPaintListener(new PaintListener(){
	        public void paintControl(PaintEvent e){
	        	e.gc.setLineWidth(4);
	            e.gc.drawLine(0,325,50,325);
	            e.gc.drawLine(50,325,50,100);
	            e.gc.drawLine(0,645,20,645);
	        }
	    });

		MessageButton = new Button(tabpage, SWT.NONE);
		MessageButton.setText("Messaage");
		MessageButton.setBounds(20, 75, 80, 50);
		MessageButton.addSelectionListener(new SelectionAdapter(){  
			public void widgetSelected(SelectionEvent e){
				gc.drawLine(50,100,120,100);
				gc.drawLine(115,95,120,100);
				gc.drawLine(115,105,120,100);
				
				gc.drawLine(730,100,780,100);
				gc.drawLine(780,100,775,95);
				gc.drawLine(780,100,775,105);
				
				gc.drawLine(220,220,220,235);
	            gc.drawLine(215,230,220,235);
	            gc.drawLine(225,230,220,235);
				message1.setText("click to continue");
				message1.setBounds(880, 200, 420, 30);
				
				String mHexValue = new String(Hex.encode(BLAKE224.Algorithm.state.data32));
				m16_value[0].setText("0x"+mHexValue);
				t2_value[0].setText("0x"+Integer.toHexString(BLAKE224.Algorithm.state.t32[0]));
				t2_value[1].setText("0x"+Integer.toHexString(BLAKE224.Algorithm.state.t32[1]));
	        }
	        public void widgetDefaultSelected(SelectionEvent e) {  	      
	        }  
	    });  
		
		SaltButton = new Button(tabpage, SWT.NONE);
		SaltButton.setText("Salt");
		SaltButton.setBounds(20, 620, 80, 50);
		SaltButton.addSelectionListener(new SelectionAdapter(){  
			public void widgetSelected(SelectionEvent e){
				gc.drawLine(100, 645, 120, 645);
				gc.drawLine(115, 640, 120, 645);
				gc.drawLine(115, 650, 120, 645);
				for(int i=0; i<8; i++){
					s4_value[i].setText("0x"+ Integer.toHexString(BLAKE224.Algorithm.state.salt32[i]));
				}
	        }
	        public void widgetDefaultSelected(SelectionEvent e) {  	      
	        }  
	    });  
        
		tutorial_text=new StyledText(tabpage, SWT.BORDER | SWT.READ_ONLY | SWT.WRAP);
		tutorial_text.setBounds(120, 10, 610, 210);
		tutorial_text.addFocusListener(new FocusAdapter() {
			@Override
			public void focusLost(FocusEvent e) {
				tutorial_text.setSelection(0, 0);
			}
		});
		tutorial_text.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.stateMask == SWT.CTRL && e.keyCode == 'a') {
					tutorial_text.selectAll();
				}
			}
		});
		tutorial_text.setEditable(false);
		tutorial_text.setFont(SWTResourceManager.getFont("Segoe UI", 11, SWT.ITALIC));
		tutorial_text.setText("BLAKE224/256\n"+ Messages.HashingView_01);
		
		
		m_panel = new Group(tabpage, SWT.BORDER| SWT.SHADOW_IN|SWT.SHADOW_OUT);
		m_panel.setBounds(780, 10, 620, 180);
		create_4X4_matrix(m_panel, "m", m16_index, m16_value, 20, 150);
		
		t_panel = new Group(tabpage, SWT.BORDER| SWT.SHADOW_IN|SWT.SHADOW_OUT);
		t_panel.setBounds(120, 235, 210, 60);
		create_2X1_matrix(t_panel, "t", t2_index, t2_value, 20, 100);
		
		c_panel = new Group(tabpage,SWT.SHADOW_IN|SWT.SHADOW_OUT);
		c_panel.setBounds(120, 305, 620, 180);
		create_4X4_matrix(c_panel, "c", c16_index, c16_value, 20, 150);
		for(int i=0; i<16; i++){
			c16_value[i].setText("0x"+ Integer.toHexString((int)(c32[i]>>5))+ Integer.toHexString((int)(c32[i])));
		}
				
		h_panel = new Group(tabpage, SWT.SHADOW_IN|SWT.SHADOW_OUT);
		h_panel.setBounds(120, 500, 420, 100);
		create_4X2_matrix(h_panel, "h", h8_index, h8_value, 20, 100);
		for(int i=0; i<8; i++){
			h8_value[i].setText("0x"+ Integer.toHexString(IV224[i]));
		}
		
		s_panel = new Group(tabpage, SWT.BORDER| SWT.SHADOW_IN|SWT.SHADOW_OUT);
		s_panel.setBounds(120, 615, 420, 60);
		create_4X1_matrix(s_panel, "s", s4_index, s4_value, 20, 100);	
	
        v0_panel=new Group(tabpage, SWT.BORDER| SWT.BORDER| SWT.SHADOW_IN|SWT.SHADOW_OUT);
        v0_panel.setBounds(880, 235, 420, 180);
        create_4X4_matrix(v0_panel,"v", v16_index, v16_value, 20, 100);
		for(int i=0;i<8;i++){
			v16_value[i].setText("h"+i);
		}
		for(int i=0;i<4;i++){
			v16_value[i+8].setText("s"+i+" XOR c"+i);
		}
		v16_value[12].setText("t0 XOR c4");
		v16_value[13].setText("t0 XOR c5");
		v16_value[14].setText("t1 XOR c6");
		v16_value[15].setText("t1 XOR c7");
		message1.addSelectionListener(new SelectionAdapter(){  
			public void widgetSelected(SelectionEvent e){
				gc.drawLine(325, 260, 880, 260);
				gc.drawLine(875, 255, 880, 260);
				gc.drawLine(875, 265, 880, 260);
				
				gc.drawLine(730, 320, 880, 320);
				gc.drawLine(875, 325, 880, 320);
				gc.drawLine(875, 315, 880, 320);
				
				gc.drawLine(530, 550, 745, 550);
				gc.drawLine(745, 550, 745, 350);
				gc.drawLine(745, 350, 880, 350);
				gc.drawLine(875, 345, 880, 350);
				gc.drawLine(875, 355, 880, 350);
				
				gc.drawLine(530, 645, 765, 645);
				gc.drawLine(765, 645, 765, 380);
				gc.drawLine(765, 380, 880, 380);
				gc.drawLine(875, 385, 880, 380);
				gc.drawLine(875, 375, 880, 380);
			
				message2.setText("click to continue");
				message2.setBounds(1080, 440, 300, 30);	
				message1.setBounds(1080, 440, 0, 0);
			}
		});

	v_panel=new Group(tabpage, SWT.BORDER| SWT.SHADOW_IN|SWT.SHADOW_OUT);
	v_panel.setBounds(780, 500, 620, 180);
	message2.addSelectionListener(new SelectionAdapter(){  
		public void widgetSelected(SelectionEvent e){
			gc.drawLine(1000, 415, 1000, 500);
			gc.drawLine(995, 495, 1000, 500);
			gc.drawLine(1005, 495, 1000, 500);
			message3.setText("click to continue");
			message3.setBounds(780, 680, 620, 30);
			message2.setBounds(1080, 440, 0, 0);
			for(int i=0;i<8;i++){
				v16_value[i].setText("0x"+(IV224[i]&0xffffffffL));
			}
			for(int i=0;i<4;i++){
				v16_value[8+i].setText("0x"+((BLAKE224.Algorithm.state.salt32[i]^c32[i])& 0xffffffffL));
			}
			v16_value[12].setText("0x"+((BLAKE224.Algorithm.state.t32[0] ^ c32[4]) & 0xffffffffL));
			v16_value[13].setText("0x"+((BLAKE224.Algorithm.state.t32[0] ^ c32[5]) & 0xffffffffL));
			v16_value[14].setText("0x"+((BLAKE224.Algorithm.state.t32[0] ^ c32[6]) & 0xffffffffL));
			v16_value[15].setText("0x"+((BLAKE224.Algorithm.state.t32[0] ^ c32[7]) & 0xffffffffL));
			
		}
	});
	create_4X4_matrix(v_panel,"v", v16_index, v16_value, 20, 150);
	

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