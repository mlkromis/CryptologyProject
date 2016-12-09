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


public class Blake_tab2 {
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
	public Group sigma_panel;
	public Label sigma_value[][]=new Label[10][16];
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
	
	public Blake_tab2(TabFolder tabFolder_input, Group tabpage_input){
		tabFolder=tabFolder_input;
		tabpage=tabpage_input;
		for(int i=0; i<10; i++){
			for(int j=0; j<16; j++){
				sigma_value[i][j]=new Label(tabpage, SWT.BORDER);
				sigma_value[i][j].setBounds(50+i*150, 50+20*j, 150, 20);
				sigma_value[i][j].setText(""+sigma[i][j]);
				sigma_value[i][j].setAlignment(SWT.CENTER);
				
			}
		}
	}
	
		
}