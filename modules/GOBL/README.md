<h1><p style="text-align: center;">GOBL Module</p></h1>

<h2>What is it for</h2>
The GoLang BuiLder (or GOBL) is intended to be used for the LCJ Ransomware.</br>
It works after using the KRAM module. While the KRAM module creates encryptors and decryptors 
containing unique RSA key pairs, GOBL creates executables for Windows, Linux and Darwin based OS.</br>

<h4>To understand how is LCJ supposed to work, please refer to the README contained in the root folder of the project.</br> Moreover, to understand how this module works, refers to the GOBL section of the PDF</h4>

<h2>Supported OS</h2>
This code has been made in order to be the less storage-eater possible. We know that most of the people
uses a 64-bit Windows system, thus, each encryptor and decryptor will have a Windows64 executable. Refer
to the table below to see the build occurrence of the supported platform, note that it is possible to change
the occurrence by editing the code at your will :

|      OS     |                     Occurrence                   |Extension|
|-------------|--------------------------------------------------|---------|
|Windows64    |<p style="text-align: center;">every file</p>     |    6    |
|Windows32    |<p style="text-align: center;">every 100 files</p>|    3    |
|Linux64      |<p style="text-align: center;">every 10 files</p> |    e6   |
|Linux32      |<p style="text-align: center;">every 150 files</p>|    e3   |
|Darwin amd64 |<p style="text-align: center;">every 50 files</p> |    a6   |

Due to the fact that this ransomware has been developped in Golang 1.15.6, it is not really possible to 
build for Darwin arm64 (M1 chip).
The extension refers to the last 1 or 2 letter/digit of the file. It is intended to differentiate the different OS/ARCH of the executables.

<h2>How to use it</h2>
It is as simple as launching the script ! But first, you need to change the variable name **"RW_path"** in the script.
The path should be the same path has the KRAM module. </br>
What this script will do is simple : Iterate through all directories and create executables of the files beginning with
either a 6 (encryptor) or a 9 (decryptor).

<h2>Useful links</h2>
* <a href="https://github.com/lisandro-git/Lets_Cry_of_Joy/tree/main/modules/KRAM">KRAM Module</a>
* <a href="https://github.com/lisandro-git/Lets_Cry_of_Joy">LCJ</a></br>
Because this project was a school based project, you can also go to <a href="https://github.com/lisandro-git/Lets_Cry_of_Joy/blob/main/PDFs/Annual_Project.pdf">this link</a>.
It contains the PDF of my project, and thus how LCJ and its modules are intended to work.
  