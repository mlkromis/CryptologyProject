#Jcryptool visualization plug-in for SHA3 candidate BLAKE224

The plug-ins won't be integrated into the Jcryptool software and released until they are authorized by Jcryptool Project leaders. For more details, please check the detail in README.md of master branch. 

##Before adding the visualization plug-in to Jcryptool, pleas also -follow the instructions in the README.MD of the master branch to construct general developing envrioment. If you have done that, please follow the instructions below.

1. SHA-3 candidates list is on the official website of NIST(National Institute of Standards and Technology) below. http://csrc.nist.gov/groups/ST/hash/sha-3/Round1/submissions_rnd1.html. The submitted materials of the candidates can all be found on this website. 

2.  To add visualization plug-ins, please firstly add the commands below into the org.jcryptool.visual.feature/feature.xml.

   <!plugin
         id="org.jcryptool.visual.sha3candidates"
         download-size="0"
         install-size="0"
         version="0.0.0"
         unpack="false"/>

3. Download the org.jcryptool.visual.sha3candidates folder. Add the project to eclipse by selecting the folder through File > Open Projects from File System > Directory... and click 'Finish'. 

4. If the plug-in in the folder doesn't work, please try compressing the zip file in the same name and replace all the contents of the original folder.

5. Launch JCryptool in eclipse, click the "Visual" in the menu, and click in "SHA3 Candidates". 

