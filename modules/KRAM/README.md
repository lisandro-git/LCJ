<h1><p style="text-align: center;">KRAM Module</p></h1>

##What is it for ?
The Key Recreating Appending Module has been developed in order to create one encryptor and decryptor, each of them
containing a unique RSA key pair, for each computer that the Ransomware will infect (Refer to the last link of this README).
It creates a folder containing a Private/Public RSA key pair and an encryptor and decryptor containing those keys.

####To understand how is LCJ supposed to work, please refer to the README contained in the root folder of the project.</br> Moreover, to understand how this module works, refers to the KRAM section of the PDF

##How to use it
You need to change the variable name **"max_rw"** and increase or decrease the value. This will create x folders containing
the key pairs, the encryptor and the decryptor.</br>
You also need to change the **"path"** variable to where you want your files to be created, and the **"dummy_path"** variable to where
is located the dummy files.

##Useful links

* <a href="https://github.com/lisandro-git/Lets_Cry_of_Joy">LCJ</a></br>
Because this project was a school based project, you can also go to <a href="https://github.com/lisandro-git/Lets_Cry_of_Joy/blob/main/PDFs/Annual_Project.pdf">this link</a>.
It contains the PDF of my project, and thus how LCJ and its modules are intended to work.
  