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
import org.jcryptool.visual.sha3candidates.algorithms.HashFunction;


public class Blake_tab {
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
	
	public Blake_tab(TabFolder tabFolder_input, Group tabpage_input){
		tabFolder=tabFolder_input;
		tabpage=tabpage_input;
		create_tab0();
	}
	
	public void create_tab0(){	
		gc = new GC(tabpage);
		gc.setLineWidth(4);
//		Hashpage = new Browser(tabpage, SWT.BORDER);
//		Hashpage.setBounds(800, 130, 300, 300);
//		Hashpage.setUrl("file:///C:/workspace1/org.jcryptool.visual.sha3candidates/nl/en/help/content/ECHOTutorial.html");
		

		
		tabpage.addPaintListener(new PaintListener(){
	        public void paintControl(PaintEvent e){
	        	e.gc.setLineWidth(4);
	            e.gc.drawLine(0,325,50,325);
	            e.gc.drawLine(50,325,50,100);
	            e.gc.drawLine(0,585,20,585);
	        }
	    });
		
		Button MessageButton = new Button(tabpage, SWT.NONE);
		MessageButton.setText("Messaage");
		MessageButton.setBounds(20, 75, 80, 50);
		MessageButton.addSelectionListener(new SelectionAdapter(){  
			public void widgetSelected(SelectionEvent e){
				gc.drawLine(100,325,120,325);
				tabItem1.setText("lol");
				String mHexValue = new String(Hex.encode(BLAKE224.Algorithm.state.data32));
				m16_value[0].setText("0x"+mHexValue);
	        }
	        public void widgetDefaultSelected(SelectionEvent e) {  	      
	        }  
	    });  
		
		Button SaltButton = new Button(tabpage, SWT.NONE);
		SaltButton.setText("Salt");
		SaltButton.setBounds(20, 560, 80, 50);
		SaltButton.addSelectionListener(new SelectionAdapter(){  
			public void widgetSelected(SelectionEvent e){
	            gc.drawLine(100, 585, 120, 585);
				tabItem1.setText("hehe");
				for(int i=0; i<8; i++){
					s4_value[i].setText("0x"+ Integer.toHexString(BLAKE224.Algorithm.state.salt32[i]));
				}
	        }
	        public void widgetDefaultSelected(SelectionEvent e) {  	      
	        }  
	    });  
		
		m_panel = new Group(tabpage, SWT.SHADOW_IN);
		m_panel.setBounds(120, 220, 610, 210);
		create_4X4_matrix(m_panel, "m", m16_index, m16_value);

		c_panel = new Group(tabpage, SWT.SHADOW_IN);
		c_panel.setBounds(120, 10, 610, 210);
		create_4X4_matrix(c_panel, "c", c16_index, c16_value);
		for(int i=0; i<16; i++){
			c16_value[i].setText("0x"+ Integer.toHexString((int)(c32[i]>>5))+ Integer.toHexString((int)(c32[i])));
		}
		
		IV_panel = new Group(tabpage, SWT.SHADOW_IN);
		IV_panel.setBounds(120, 430, 410, 110);
		create_4X2_matrix(IV_panel, "IV", IV8_index, IV8_value);
		for(int i=0; i<8; i++){
			IV8_value[i].setText("0x"+ Integer.toHexString(IV224[i]));
		}
		
		s_panel = new Group(tabpage, SWT.SHADOW_IN);
		s_panel.setBounds(120, 550, 410, 55);
		create_4X1_matrix(s_panel, "s", s4_index, s4_value);		
}
	
	public void create_4X1_matrix(Group s_panel, String name, Label s4_index[], Text s4_value[]){
		for(int k=0; k<4; k++){
			s4_index[k] = new Label(s_panel, SWT.NONE);
			s4_index[k].setBounds(5+100*k, 5, 100, 25);
			s4_index[k].setText(name+k);
			s4_value[k] = new Text(s_panel, SWT.BORDER);
			s4_value[k].setBounds(5+100*k, 30, 100, 25);
		}
	}
	
	public void create_4X2_matrix(Group IV_panel, String name, Label IV8_index[], Text IV8_value[]){
		for(int k=0; k<4; k++){
			IV8_index[k] = new Label(IV_panel, SWT.NONE);
			IV8_index[k].setBounds(5+100*k, 5, 100, 25);
			IV8_index[k].setText(name+k);
			IV8_value[k] = new Text(IV_panel, SWT.BORDER);
			IV8_value[k].setBounds(5+100*k, 30, 100, 25);
			IV8_index[k+4] = new Label(IV_panel, SWT.NONE);
			IV8_index[k+4].setBounds(5+100*k, 55, 100, 25);
			IV8_index[k+4].setText(name+k+4);
			IV8_value[k+4] = new Text(IV_panel, SWT.BORDER);
			IV8_value[k+4].setBounds(5+100*k, 80, 100, 25);
		}

	}
	public void create_4X4_matrix(Group c_panel, String name, Label c16_index[], Text c16_value[]){
		for(int i=0; i<4; i++){
			c16_index[i] = new Label(c_panel, SWT.NONE);
			c16_index[i].setBounds(5+150*i, 5, 150, 25);
			c16_index[i].setText(name+i);
		}
		for(int i=0; i<4; i++){
			c16_value[i] = new Text(c_panel, SWT.BORDER);
			c16_value[i].setBounds(5+150*i, 30, 150, 25);
		}
		for(int i=4; i<8; i++){
			c16_index[i] = new Label(c_panel, SWT.NONE);
			c16_index[i].setBounds(5+150*(i-c16_index.length/4), 55, 150, 25);
			c16_index[i].setText(name+i);
		}
		for(int i=4; i<8; i++){
			c16_value[i] = new Text(c_panel, SWT.BORDER);
			c16_value[i].setBounds(5+150*(i-4), 80, 150, 25);
		}
		for(int i=8; i<12; i++){
			c16_index[i] = new Label(c_panel, SWT.NONE);
			c16_index[i].setBounds(5+150*(i-8), 105, 150, 25);
			c16_index[i].setText(name+i);
		}
		for(int i=8; i<12; i++){
			c16_value[i] = new Text(c_panel, SWT.BORDER);
			c16_value[i].setBounds(5+150*(i-8), 130, 150, 25);
		}
		for(int i=12; i<16; i++){
			c16_index[i] = new Label(c_panel, SWT.NONE);
			c16_index[i].setBounds(5+150*(i-12), 155, 150, 25);
			c16_index[i].setText(name+i);
		}
		for(int i=12; i<16; i++){
			c16_value[i] = new Text(c_panel, SWT.BORDER);
			c16_value[i].setBounds(5+150*(i-12), 180, 150, 25);
		}
	}
	
	public void create_m(Blake_Action BLAKE, String inputText, String saltText){
		BLAKE224=BLAKE;
		c16_index[1].setText("lol");
		c16_value[1].setText("lol");
//		String mHexValue = new String(Hex.encode(BLAKE224.Algorithm.state.data32));
//		m16_value[0].setText("0x"+mHexValue);

//		if(saltText.length()==32){
//			for(int i=0; i<8; i++){
//				s4_value[i].setText("0x"+ Integer.toHexString(BLAKE224.Algorithm.state.salt32[i]));
//			}
//		}
		
	}
}