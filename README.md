1. If the program in the folder doesn't work, try the program in the zip file.
2. SHA-3 candidates list is on the official website of NIST(National Institute of Standards and Technology) below.
http://csrc.nist.gov/groups/ST/hash/sha-3/Round1/submissions_rnd1.html

The submitted materials of the candidates can all be found on this website. 

3.  For visualization, please add the commands below into the org.jcryptool.visual.feature/feature.xml. Just take a look at the content of the feature.xml before you do anything. You know where to add those commands.

   <plugin
         id="org.jcryptool.visual.sha3candidates"
         download-size="0"
         install-size="0"
         version="0.0.0"
         unpack="false"/>

Download the org.jcryptool.visual.sha3candidates folder. Add the project to eclipse by selecting the folder through File > Open Projects from File System > Directory... and click 'Finish'. 

Launch JCryptool in eclipse, click the "Visual" in the menu, and click in "SHA3 Candidates". 
