/*============================================================================
* Name        : sslemail.c
* Compiling   : gcc -c -o sslemail.o sslemail.c
*               gcc -o sslemail sslemail.o -lssl -lcrypto
*=============================================================================
*/

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <time.h>
#include <signal.h>

#define SSL_READ_SIZE 500    // Max reading each time from SSL connection
#define STRINGDATE_SIZE 100  // String size for date/time
#define WORK_START 1         // For create email content to start work
#define WORK_STOP 2          // For create email content to stop work
#define NO_WORK 3            // Today is off day, no need to send email, 
#define JUST_WAIT 4          // Just wait, no need to send email yet
#define HALT_ALL 5           // No need to send email anymore, can stop whole program

#define SSL_HOST "SSL host name/address" // Destination host for SSL connection
#define SSL_PORT 465         // Destination port for SSL connection
#define PUTTY_CMD "~/putty/unix/putty -load Save_session" //putty command to load saved session
#define HELLO_SERVER "helo EMAILSERVER\n" // Handsake command to email server
#define AUTH_PLAIN "auth plain plain_user_password_in_base64_encoding\n" // Email user name and password in base64 encode

SSL *ssl;  //SSL socket
int sock;  //SSL socket reference

// To receive data from SSL connection and store in buffer buf
int recvPacket(char *buf)
{
    int len = SSL_READ_SIZE;
    len = SSL_read(ssl, buf, SSL_READ_SIZE);
    if (len >= 0) buf[len] = 0; 
    printf("Received: %s\n", buf);

    if (len < 0) {
        int err = SSL_get_error(ssl, len);
        if (err == SSL_ERROR_WANT_READ)
                return EXIT_SUCCESS;
        if (err == SSL_ERROR_WANT_WRITE)
            return EXIT_SUCCESS;
        if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL)
            return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

// To send data to the SSL connection from buffer buf
int sendPacket(const char *buf)
{
    int len = SSL_write(ssl, buf, strlen(buf));
    printf("Sent: %s\n", buf);

    if (len < 0) {
        int err = SSL_get_error(ssl, len);
        switch (err) {
        case SSL_ERROR_WANT_WRITE:
            return EXIT_SUCCESS;
        case SSL_ERROR_WANT_READ:
            return EXIT_SUCCESS;
        case SSL_ERROR_ZERO_RETURN:
        case SSL_ERROR_SYSCALL:
        case SSL_ERROR_SSL:
        default:
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}
    
// Connect to the destination using SSL
int connectSSL()
{
    int s, err = 0;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        printf("Error creating socket.\n");
        return EXIT_FAILURE;
    }
    struct sockaddr_in sa;
    memset (&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = inet_addr(SSL_HOST); // Local host address
    sa.sin_port        = htons (SSL_PORT); 
    socklen_t socklen = sizeof(sa);
    if (connect(s, (struct sockaddr *)&sa, socklen)) {
        printf("Error connecting to server.\n");
        return EXIT_FAILURE;
    }
    SSL_library_init();
    SSLeay_add_ssl_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *meth = TLSv1_2_client_method();
    SSL_CTX *ctx = SSL_CTX_new (meth);
    ssl = SSL_new (ctx);
    if (!ssl) {
        printf("Error creating SSL.\n");
        logSSL();
        return EXIT_FAILURE;
    }
    sock = SSL_get_fd(ssl);
    SSL_set_fd(ssl, s);
    err = SSL_connect(ssl);
    if (err <= 0) {
        printf("Error creating SSL connection.  err=%x\n", err);
        logSSL();
        fflush(stdout);
        return EXIT_FAILURE;
    }
    printf ("SSL connection using %s\n", SSL_get_cipher (ssl));
    return EXIT_SUCCESS;    
}

void logSSL()
{
    int err;
    while (err = ERR_get_error()) {
        char *str = ERR_error_string(err, 0);
        if (!str)
            return;
        printf("%s\n", str);
        fflush(stdout);
    }
}

// Get today date and return the string in "dd Mmm yyyy" format (e.g 11 Jan 2021)
int getToday(char *strDate)
{
    time_t t;
    struct tm *tmp;

    t = time(NULL);
    tmp = localtime(&t);
    if (tmp == NULL) {
        perror("localtime");
        return EXIT_FAILURE;
    }

    if (strftime(strDate, STRINGDATE_SIZE, "%d %b %Y", tmp) == 0) {
        fprintf(stderr, "strftime returned 0");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;    
}

// Check if today is holiday (Sat, Sun or Public holiday)
int isHoliday()
{
    char arrHoliday [][STRINGDATE_SIZE] = { // Public holiday to Apr 2021 only
                                            {"25 Dec 2020"},  
                                            {"01 Jan 2021"},
                                            {"12 Feb 2021"},
                                            {"15 Feb 2021"},   
                                            {"02 Apr 2021"}
                                          };    
    time_t t;
    struct tm *tmp;
    char strDate[STRINGDATE_SIZE];

    t = time(NULL);
    tmp = localtime(&t);
    if (tmp == NULL) {
        perror("localtime");
        return EXIT_FAILURE;
    }
    if (tmp->tm_wday == 0 || tmp->tm_wday == 7) 
        return 1; // Is holiday - weekend

    int err = getToday(strDate);
    for (int i = 0; i < sizeof(arrHoliday)/STRINGDATE_SIZE; i++) {
        if (strcmp(strDate, arrHoliday[i]) == 0) 
            return 1; // Is holiday - public holiday
    }

    return EXIT_SUCCESS; // Not a holiday
}

// Create email content to buf, depends on option
void createEmail(int option, char *buf)
{
    char strDate[STRINGDATE_SIZE];
    int err = 0;

    err = getToday(strDate);

    // Email header, for show only, real sender and recipeints are already set
    strcpy(buf, "Data\nFrom: \"ABC XYZ\" <youremail@xxx.xxx>\n" \
    "To: XXX YYY <xxx@xxx.xxx>, YYY ZZZ <xxx@xxx.xxx>\n" \
    "CC: zzz@xxx.xxx\n");

    if (option == WORK_START) {
        strcat(buf, "Subject: Test start today: ");
        strcat(buf, strDate);
        strcat(buf, " - End\n");
        strcat(buf, "\n" \
                    "Test start line 1\n" \
                    "Test start line 2\n" \
                    "\n");
    } else if (option == WORK_STOP) {
        strcat(buf, "Subject: Test stop today: ");
        strcat(buf, strDate);
        strcat(buf, " - End\n");
        strcat(buf, "\n" \
                    "Test stop line 1\n" \
                    "Test stop line 2\n" \
                    "\n");
    }  //else  invalid option

    strcat(buf, "Regards,\n" \
                "SGH858\n" \
                ".\n");  // This final dot is important, it tells Email server to send email

}

// Send email start work/stop work depend on option
int sendEmail(int option)
{
    int err = 0;
    char buf[100000];

    // Send helo
    char request[10000] = HELLO_SERVER;       
    sendPacket(request);
    err = recvPacket(buf);

    // Send authentication
    strcpy(request, AUTH_PLAIN);
    sendPacket(request);
    err = recvPacket(buf);

    // From real email user, changed it to your email
    strcpy(request, "mail from: fromuser@xxx.xxx.xxx\n"); 
    sendPacket(request);
    err = recvPacket(buf);

    strcpy(request, "rcpt to:  recipient1@xxx.xxx\n");    // To this real recipient 
    sendPacket(request);
    err = recvPacket(buf);

    strcpy(request, "rcpt to:  recipient2@xxx.xxx\n");    // To additional recipient
    sendPacket(request);
    err = recvPacket(buf);

    createEmail(option, request);

    sendPacket(request);
    err = recvPacket(buf);

    if (!err) printf("Email sent!\n");    
    return err;    
} 

// Check for need to send email, which type of email (start/stop) or stop whole program
int checkToSendEmail(int *secondToWait)
{
    time_t apr12021, today842am, today11am, today615pm, today9pm, currenttime;
    struct tm *tmp;
    int ranMin;
    
    srand(time(NULL));
    ranMin = rand() % 20; // Added random 20 mins waiting to send email

    currenttime = time(NULL);
    tmp = localtime(&currenttime); 
   
    tmp->tm_sec = 0; tmp->tm_min = 42; tmp->tm_hour = 8;
    today842am = mktime(tmp);

    tmp->tm_sec = 0; tmp->tm_min = 0; tmp->tm_hour = 11;
    today11am = mktime(tmp);

    tmp->tm_sec = 0; tmp->tm_min = 15; tmp->tm_hour = 18;
    today615pm = mktime(tmp);

    tmp->tm_sec = 0; tmp->tm_min = 0; tmp->tm_hour = 21;
    today9pm = mktime(tmp);

    strptime("01 Apr 2021 00:00:00", "%d %b %Y %H:%M:%S",tmp);
    apr12021 = mktime(tmp);

    if (difftime(currenttime, apr12021) > 0) {
        return HALT_ALL; // No need to send email anymore, the program can exit
    } else {
        if (isHoliday()) {
            //skip to next morning
            *secondToWait = difftime(today842am + 60*60*24, currenttime) + ranMin*60;
            return NO_WORK; 
        } else if (difftime(currenttime, today842am) >= 0 && difftime(currenttime, today11am) <= 0) {
            // Need to send start work email
            *secondToWait = difftime(today615pm, currenttime) + ranMin*60; // To the afternoon 6:15pm
            return WORK_START; 
        } else if (difftime(currenttime, today615pm) >= 0 && difftime(currenttime, today9pm) <= 0) {
            // Need to send stop email
            *secondToWait = difftime(today842am + 60*60*24, currenttime) + ranMin*60; // To the next morning 8:42am
            return WORK_STOP; 
        } else if (difftime(currenttime, today842am) < 0) {
            // Need to wait to 842am and send email
            *secondToWait = difftime(today842am, currenttime) + ranMin*60; // Wait to the 842am
            return JUST_WAIT; 
        } else if (difftime(currenttime, today615pm) < 0) {                
            // Need to wait to 615pm and send email
            *secondToWait = difftime(today615pm, currenttime) + ranMin*60; // Wait to 615pm
            return JUST_WAIT; 
        } else {
            // Need to wait to 842am tomorrow and send email
            *secondToWait = difftime(today842am + 60*60*24, currenttime) + ranMin*60; // To the next morning 8:42am
            return JUST_WAIT;
        }
    }
}

void killPutty(int pid)
{
    char pidStr[1024];
    if (pid > 0) 
        sprintf(pidStr, "pkill -f putty; kill -9 %d", pid);
    else
        sprintf(pidStr, "pkill -f putty");
    FILE *cmd = popen(pidStr, "r");
    fgets(pidStr, 1024, cmd);  // Kill all process with name putty and child process
    pclose(cmd);
    sleep(5); // Let wait 5 sec for child process to be killed
}

int main(int argc, char *argv[])
{
    int err = 0, emailOption = -1;

    char buf[100000];
    char pidStr[1024];
    pid_t childpid = -1;
    int stop = 0, secondToWait = 0;

    while (!stop) {
        emailOption = checkToSendEmail(&secondToWait);
        switch (emailOption) {
            case HALT_ALL:  // Stop main and child processes, exit program
                stop = 1;
                break;
            case NO_WORK:  // Holiday, no need to send email
                printf ("Today is off day, wait for %d seconds for tomorrow morning.\n", secondToWait);
                sleep(secondToWait); // sleep until next day morning
                break;                
            case WORK_START:  // Need to send start work email, sleep until afternoon
            case WORK_STOP:  // Need to send stop work email, sleep until next day morning                
                printf ("Send start/stop work email and wait for %d seconds to send next email.\n", secondToWait);                
                childpid = fork();
                if (childpid == 0) { 
                    // Child process code run here
                    printf("Hello from Child!\n");
                    FILE *cmd = popen(PUTTY_CMD, "r");
                    fgets(pidStr, 1024, cmd);  // Start process putty
                    pclose(cmd);
                    return EXIT_SUCCESS;
                } else {
                    // Parent process code run here
                    sleep(5); //Wait 5 secs for child process to run putty
                    printf("Hello from Parent, childpid is %d!\n", childpid); 
                    err = connectSSL();                    
                    if (!err) {
                        recvPacket(buf);        
                        sendEmail(emailOption);
                        sleep(5); //Wait 5 secs for email sent
                    } else {
                        secondToWait = 300;  // Problem with SSL connection, wait 5mins to try again
                        printf ("Error in sending email, waiting for 5 mins to try again.\n");
                    }
                    killPutty(childpid);  // Kill child process and putty
                    wait(2);
                    sleep(secondToWait);                                        
                }                       
                break;          
            case JUST_WAIT:  // No need to send email yet, just wait
                printf ("No need to send email yet, wait for %d seconds before sending.\n", secondToWait);
                sleep(secondToWait);
                break;
        }                  
    }
    return EXIT_SUCCESS;
}