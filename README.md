<h1>Changelog</h1>
<ul>
    <li>Changed KRAL module name to KRAM module</li>
</ul>

<h3>Encryptor</h3>
<ul>
    <li>Changed opened file limit from 1GB to 900MB</li>
    <li>Changed aes.BlockSize (from 16 to 32, (in crypto/cipher lib, will be commited after)</li>
    <li>If a size is superior to 150MB, it will only encrypt the first 10MB. Thus, the file structure will be : 
        <br>Encrypted 10MB 
        <br>Rest of the file (not encrypted)
        <br>The file will not be lisible even though it has the 10 first megabytes encrypted 
    </li>
    <li>Added 45 extensions to the blacklist</li>
    <li>Commented some print, and removed useless comments, removed non-used function</li>
</ul>

<h3>Decryptor</h3>
<ul>
    <li>It can now decipher file parts (see encryptor)</li>
    <li>Changed the structure of the DecodeBase64 function</li>
    <li>Removed struct and functions tied to the struct</li>
</ul>

<h3>KRAM (Key Recreating Appending Module)</h3>
<ul>
    <li>Changed the encryptor_dummy and the decryptor_dummy content with the new version of the encryptor and the decryptor</li>
</ul>

<h3>EPM (Execution Policy Module)</h3>
<ul>
    <li></li>
</ul>

<h3>GOBL (GoLang BuiLder)</h3>
<ul>
    <li></li>
</ul>

<h2>Languages</h2>
<ul>
    <li></li>
</ul>

<h2> Upcoming </h2>
<ul> 
    <li>Evasion Module</li>
</ul>

<h2>FileLog</h2>
<ul>
    <li>Files added</li>
    <ul>
        <li></li>
    </ul>
    <li>Directories added</li>
    <ul>
       <li></li>
    </ul>
</ul>

<H1>Version Number : V1.4</H1>
