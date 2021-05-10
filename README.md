<h1> Changelog</h1>
<ul>
    <li>The ransom is now calculated on how many files it encrypted (multiplied by 1.25)</li>
    <li>LCJ can now encrypt specific extensions</li>
    <li>Addressed some issues with the KRAL module</li>
</ul>

<h2>Languages</h2>
<ul>
    <li>Changed some sentences, still not done</li>
    <li></li>
    <li></li>
</ul>

<h2> Upcoming </h2>

<ul>
    <li>After the new encryptor and decryptor is made, turn them into ".exe"</li>
    <li>Correction of the ransomware message</li>
    <li>Ransomware message translated in other languages</li>
    <li>Not encrypting the default folders contained in the C: directory</li>
    <li>EPM module (deleting the shadow copies)
        <ul>
            <li>Translated by Execution Policy Modifier</li>    
            <li>Go code that will spawn a powershell script before encrypting the system</li>    
            <li>It's job is to delete shadow copies after the privilege escalation script has been completed</li>    
            <li>It will add an entry in the Window's Regedit in order to work successfully</li>    
        </ul>
    </li>
    <li></li>
</ul>

Files changed : 
    - encryptor.go
    - lang.fr

Files Added :
    - W_default_files
    -- File that stores the default root folder, so that it won't be deleted when the ransomware will start his job