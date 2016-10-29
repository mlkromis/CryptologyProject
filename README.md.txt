1. SHA-3 candidates list is on the official website of NIST(National Institute of Standards and Technology) below.
http://csrc.nist.gov/groups/ST/hash/sha-3/Round1/submissions_rnd1.html

The submitted materials of the candidates can all be found on this website. 

2.  For visualization, please add the codes below into the org.jcryptool.visual.feature/feature.xml. Just take a look at the content of the feature.xml before you do anything. You know where to add those codes.

   <plugin
         id="org.jcryptool.visual.sha3candidates"
         download-size="0"
         install-size="0"
         version="0.0.0"
         unpack="false"/>

Then put org.jcryptool.visual.SHA3_0.9.9.jar in the directory $JCrypToolPATH\dropins\. $JCrypToolPATH is the path where you installed JCryptool.

Launch JCryptool through eclipse, click the "Visual" in the menu, and click in "SHA3 Candidates". 
It looks like dialogue rather than visualization. But it's modified from official hashing visualization plug-in. By now only Echo and Keccak have been finished. And I'm working on other candidates and trying to make the visualization cooler.

I'll update the jar file in the future. If you're interested in what's going on, all you need to do is to move the newest jar file into $JCrypToolPATH\dropins\, launch jcryptool and check it out. 
   
