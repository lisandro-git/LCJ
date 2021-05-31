<h1>Changelog</h1>
<ul>
    <li>Added version for LCJ</li>
</ul>

<h3>Encryptor</h3>
<ul>
    <li>Added Goroutines to the code, so that LCJ can encrypt faster</li>
    <li>
        The encryptor won't encrypt if the total file opened is superior to 1Gb.
        This has been made for scalability
    </li>
    <li>
        If a file size is superior to 150MB, it will encrypt the 150mb first bytes, and append it 
        to the end of the file
    </li>
</ul>

<h3>EPM</h3>
<ul>
    <li></li>
</ul>

<h3>GOBL</h3>
<ul>
    <li></li>
</ul>

<h2>Languages</h2>
<ul>
    <li></li>
</ul>

<h2> Upcoming </h2>
<ul> 
    <li>After the new encryptor and decryptor is made, turn them into ".exe"</li>
    <li>Correction of the ransomware message</li>
    <li>Ransomware message translated in other languages</li>
    <li>Test about the encryption of the blacklisted extensions</li>
    <li>EPM module (deleting the shadow copies) </li>
    <ul> 
        <li>Translated by Execution Policy Modifier</li>
        <li>Go code that will spawn a powershell script before encrypting the system</li>
        <li>It's job is to delete shadow copies after the privilege escalation script has been completed</li>
        <li>It will add an entry in the Window's Regedit in order to work successfully</li>
    </ul>
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

<H1>Version Number : V1.1</H1>
