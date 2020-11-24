## OpenSSL Email over ssh Tunnels in Linux/Ubuntu
This small tool (sslemail) allows you to send email over SSL tunnels of ssh connection to email server (using SSL connection). I use putty to connect and setup tunnels to my work place SSH server/Email server. You can use any program that can do that job too.

Once putty is installed and setup properly. This sslemail tool will open a child process to run putty and setup tunnel to email server. The main process will open a ssl connection to email server through that tunnel. It then sends whatever email needed, closes all the connections (ssl connection to email server, putty tunnels, child process) and wait for the next opportunity to send email. 

Currently the sslemail tool will send 2 emails (1 in the morning 942am-11am, 1 in the evening 615pm-9pm) on the working days only. The program will exit automatically after 31 March 2021.

You can customize all these, e.g send email to target group of users at different time, day, season repeatedly etc.

To use this tool, you have to do the following steps:
### Step 1: Install and setup putty for ubuntu 
1. Clone Github putty
```
git clone https://github.com/github/putty
```
2. Install prerequisite package for putty in Linux
```
sudo apt install automake autoconf libgtk-3-dev
```
3. Compile and make putty binaries
```
cd putty
mkfiles.pl; mkauto.sh
cd unix
./configure
make
```
The putty binary is placed in the ./putty/unix directory
### Step 2: Set up putty
Setup the saved putty session to SSH server. Make sure the putty session had tunnel to email server.

### Step 3: Compile the sslemail tool
1. Change the following in the code to your own parameters
```
#define SSL_HOST "SSL host name/address" // Destination host for SSL connection
#define SSL_PORT 465       // Destination port for SSL connection
#define PUTTY_CMD "~/putty/unix/putty -load Save_session" //putty command to load saved session
#define HELLO_SERVER "helo EMAILSERVER\n" // Handsake command to email server
#define AUTH_PLAIN "auth plain plain_user_password_in_base64_encoding\n" //Email user name and password in base64 encode
```
2. Install the OpenSSL development package
```
sudo apt install apt-get install libssl-dev
```
3. Compile and run the code
```
./csslemail.sh 
```
### Notes
In the program, this tool uses the following SMTP commands to communicate with the email server:
```
Sent: 
helo MAILSERVER
Expected reply: 250 MAILSERVERxxx.xxx.xxx.xxx
Sent: 
auth plain user_password_base64_encoding
Expected reply: 235 2.7.0 Authentication successful
Sent: 
mail from: fromuser@xxx.xxx.xxx
Expected reply: 250 2.1.0 Ok
Sent: 
rcpt to:  recipient1@xxx.xxx // This is the real recipient
Expected reply: 250 2.1.5 Ok
Sent: 
rcpt to:  recipient2@xxx.xxx // This is another real recipient
Expected reply: 250 2.1.5 Ok
Sent: Data
From: "ABC" abc@xxx.xxx.xxx 
To: XYZ <xyz@xxx.xxx>, CDF <cdf@xxx.xxx>  // This is just for show in the email header
CC: xxx@xxx.xxx
Subject: Test Subject
\n
Test 1
Test 2
\n
Regards,
SGH858
.  // This final single dot is the must for email server to send email
Expected reply: 354 End data with <CR><LF>.<CR><LF>
                250 2.0.0 Ok: queued as 1264725ACF7
```
To get the plain text for user_password_base64_encoding, please use the perl command:
```
perl -MMIME::Base64 -e 'print encode_base64("\000USER_NAME\000PASSWORD")'
\\ Don't remove \000
```
This repo is released under The GPL Licenses

### Acknowledgment: The SSL connection code is developed from https://stackoverflow.com/questions/41229601/openssl-in-c-socket-connection-https-client
