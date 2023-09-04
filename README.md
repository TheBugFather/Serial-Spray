<div align="center" style="font-family: monospace">
<h1>Serial-Spray</h1>

![alt text](https://github.com/ngimb64/Serial-Spray/blob/main/Serial_Spray.png?raw=true)<br>
&#9745;&#65039; Bandit verified &nbsp;|&nbsp; &#9745;&#65039; Synk verified &nbsp;|&nbsp; &#9745;&#65039; Pylint verified 9.84/10
<br><br>
</div>

## **Notice**
> This tool may be used for legal purposes only.<br>
> Users take full responsibility for any actions performed using this tool.<br>
> The author accepts no liability for damage caused by this tool.<br>
> If these terms are not acceptable to you, then do not use this tool.

## Purpose
Serial Spray is a tool that generates all the libraries in ysoserial with RCE capabilities and generates
input payload for each library with corresponding compression/encoding process specified in the output chain.
If the target is vulnerable to RCE Java serialization attack with common ysoserial library, this tool helps
automating crafting payload lists that can be fuzzed with the Burp Suite Intruder.

### License
The program is licensed under [GNU Public License v3.0](LICENSE.md)

### Contributions or Issues
[CONTRIBUTING](CONTRIBUTING.md)

## Installation
Start by running the venv and packages installation script:<br>
    `python3 setup.py venv`

Once installed, the venv can be activated from project root with:<br>
    `cd venv/bin; source activate; cd ../..`

## Usage example
`python3 serial_spray.py --out_file=/tmp/serial_wordlist.txt ./ysoserial.jar  'dig <collaborator_domain>' 'gzip|base64-url'`

**Note**: --out_file is an optional argument and if not used the default wordlist named "ss_wordlist.txt" will be generated in same directory

<br>

### Libraries to potentially add later (https://blog.afine.com/testing-and-exploiting-java-deserialization-in-2021-e762f3e43ca2)
- AspectJWeaver
- C3P0
- Clojure
- FileUpload1
- Jython1
- JRMPClient
- JRMPListener
- MyFaces2
- JSON1
- URLDNS
- Wicket