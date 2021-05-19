<h1>Changelog</h1>
<ul>
    <li>Added Windows and Linux Whitelist and Blacklist []string variables : they contain files that will be encrypted (whitelist) and saved (blacklist)</li>
    <li>OS and windows drive detection</li>
    <li>New GOBL module -> GOlang BuiLder will turn encryptors into executable for Linux and Windows</li>
</ul>

<h3>Encryptor</h3>
<ul>
    <li>Changed list_dir function : it can now detect Linux/Windows drives, and return all the files that needs to be returned</li>
    <li>LCJ does not encrypt default folders in both Linux and Windows</li>
    <li>LCJ now encrypts everything, except specified extensions (has to be tested)</li>
</ul>

<h3>EPM</h3>
<ul>
    <li>No changes done, nothing added, still upcoming</li>
</ul>

<h3>GOBL</h3>
<ul>
    <li>New module, changes are to be made</li>
</ul>

<h2>Languages</h2>
<ul>
    <li>No changes made</li>
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
        <li>exeution_policy_modifier.go</li>
        <li>golang_modifier.go</li>
    </ul>
    <li>Directories added</li>
    <ul>
        <li>GOBL</li>
    </ul>
</ul>
