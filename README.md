<h1> Changelog</h1>
- Added decryption, encryption folder <br>
- Added decryptor.go <br>
- Added languages folder, containing 14 languages. See README in this folder for more informations
<ul>
    <li>With the help of a private RSA key, you can decrypt your files</li>
    <li>The decryption program will decrypt the files in the order that they appear on the program</li>
    <li>Like the encryption program, it will delete the .LCJ files, but will not zero the files before</li>
    <li>The decryption program will decrypt the encrypted key file, in order to be able to work</li>
</ul>
- Deleted functions in both encryptor/decryptor program, to make them the lighter possible</br>

<h2>The KRAL module</h2>
- File name : key_changer.go <br>
The KRAL module is a program that generates random key pairs, and puts the public key in
encryptor, and the private key in decryptor. It does this n times, in order to have a stock of
ranswomwares before the attack.

<h1> Upcoming </h1>
- Automation xxx (add name for the script)<br>
<ul>
    <li>Generate RSA key pairs</li>
    <li>Create a new LCJ executable (encryptor/decryptor) files with newly created RSA key pairs</li>
    <li>Change the public key in encryptor; change the prvate key in decryptor</li>
    <li>Put the 2 new executables in folder</li>
</ul>
