/* A threaded server in the internet domain using TCP
   The port number is passed as an argument */
#include <stdio.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <ctype.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>


#define BUFFERLENGTH 256
#define MAX_BUFFER 7000
#define THREAD_IN_USE 0
#define THREAD_FINISHED 1
#define THREAD_AVAILABLE 2
#define THREADS_ALLOCATED 10

struct firewallQuery{
  char query[256];
  struct firewallQuery *next;
};

struct firewallRule_t {
    // int array for IPs --> [num1,num2,num3,num4]
    int ipaddr1[4];
    int ipaddr2[4];
    // int for ports
    int port1;
    int port2;
    struct firewallQuery *queryList;
};

// Structure representing linked list for storing firewall rules
struct firewallRules_t {
    // Current node
    struct firewallRule_t *rule;
    // Next node
    struct firewallRules_t *next;
};
    
struct ruleErrors_t{
    char * line;
    struct ruleErrors_t *next;
};

struct firewallRules_t *allRules = NULL, *tmp;
struct ruleErrors_t *next;
int noOfRules = 0;


// Function for printing IP Address (argument -> int *ipaddr -> Array of Integer)
void printIPaddress (int *ipaddr) {
    // [num1, num2, num3, num4]
    printf("%d.%d.%d.%d", ipaddr[0],ipaddr[1],ipaddr[2],ipaddr[3]);
}


// Function to compare IP Address (arguments -> two arrays of Inetger)
int compareIPAddresses (int *ipaddr1, int *ipaddr2) {
    int i;

    for (i = 0; i < 4; i++) {
	    if(ipaddr1[i] > ipaddr2[i]){
	        return 1;
	    }
	    else if(ipaddr1[i] < ipaddr2[i]) {
	        return -1;
	    }
    }
    return 0;
}


// Printing the rule (argument -> pointer to struct firewallRule_t)
void printRule (struct firewallRule_t *rule) {
    // printing IP1
	printf ("Rule: %d.%d.%d.%d", rule->ipaddr1[0],rule->ipaddr1[1],rule->ipaddr1[2],rule->ipaddr1[3]);
	// Check IP2 existence
    if (rule->ipaddr2[0] != -1) {
	    printf ("-");
		printIPaddress(rule->ipaddr2);
	}
    // printing Port 1
	printf (" %d", rule->port1);
    // Check Port 2 existence
	if (rule->port2 != -1) {
	    printf ("-");
	    printf ("%d", rule->port2);
	}
	printf ("\n");
}

void printQueries(struct firewallRule_t *rule){
  struct firewallQuery *currentQuery = rule->queryList;

  while(currentQuery != NULL){
    printf("Query: %s\n", currentQuery->query);
    currentQuery= currentQuery->next;
  }
}

//parses one IP address. Returns NULL if text does not start with a valid IP address, and a pointer  to the first cha
// char *text -> a pointer to the first character in the array 
char *parseIPaddress (int *ipaddr, char *text) {
    char *oldPos, *newPos;
    long int addr;
    int i;

    oldPos = text;
    for (i = 0; i <4; i++) {
	    if (oldPos == NULL || *oldPos < '0' || *oldPos > '9') {
	        return NULL;
	    }   
        // Convert a string to long integer
	    addr = strtol(oldPos, &newPos, 10);
        // newPos -> point to the first character after the converted string
	    if (newPos == oldPos) {
	        return NULL;
	    }

	    if ((addr < 0)  || addr > 255) {
	        ipaddr[0] = -1;
	        return NULL;
	    }

	    if (i < 3) {
	        if ((newPos == NULL) || (*newPos != '.')) {
		        ipaddr[0] = -1;
		        return NULL;
	        }
	        else newPos++;
	    }
	    else if ((newPos == NULL) || ((*newPos != ' ') && (*newPos != '-'))) {
	        ipaddr[0] = -1;
	        return NULL;
        }
	    ipaddr[i] = addr;
	    oldPos = newPos;
    }
    return newPos;
}

// Compare function for qsort
int compareRules (const void *arg1, const void *arg2) {
    struct firewallRules_t *rule1, *rule2;

    
    rule1 = *((struct firewallRules_t **) arg1);
    rule2 = *((struct firewallRules_t **) arg2);
    if (rule1->rule->port1 < rule2->rule->port1) {
	return -1;
    }
    else if (rule1->rule->port1 > rule2->rule->port1) {
	return 1;
    }
    else 
	return (compareIPAddresses (rule1->rule->ipaddr1, rule2->rule->ipaddr1));
}

										  
struct firewallRules_t *sortRules(struct firewallRules_t *rules, int noOfRules) {
    struct firewallRules_t **allRules, **tmp, *sortedRules; 
    int i;

    /* empty list is already sorted; rest of the function assumes noOfRules > 0 */
    if (noOfRules == 0) {
	    return NULL;
    }
    
    allRules = malloc(sizeof (struct firewallRules_t *) * noOfRules);
    tmp = allRules;
    while (rules) {
	    *tmp = rules;
	    tmp++;
	    rules = rules->next;
    }
    qsort (allRules, noOfRules, sizeof(struct firewallRules_t *), compareRules);

    for (i = 0; i < noOfRules-1; i++) {
        allRules[i]->next = allRules[i+1];
    }
    allRules[noOfRules -1]->next = NULL;
    
    sortedRules = allRules[0];
    free(allRules);
    return sortedRules;
    // return a head of linked list of sortef firewall rules
}

// Parsing port number 
char *parsePort (int *port, char *text) {
    char *newPos;

    // Check whether input string (text) is null or the first number is not a digit
    if ((text == NULL) || (*text < '0') || (*text > '9')) {
	    return NULL;
    }


    *port = strtol(text, &newPos, 10);
    if (newPos == text) {
	    *port = -1;
	    return NULL;
    }

    if ((*port < 0) || (*port > 65535)) {
	    *port = -1;
	    return NULL;
    }
    return newPos;
}
	

struct firewallRule_t *readRule (char * line, struct firewallRule_t *newRule) {
    char *pos;

    // allocatre memory for the firewall structure
    // Call parseIpAdress and feed in ipAdd1 array of the structure.
    pos = parseIPaddress (newRule->ipaddr1, line);

    if ((pos == NULL) || (newRule->ipaddr1[0] == -1)) {
	    free (newRule);
	    return NULL;
    }
    if (*pos == '-') {
	// read second IP address
        pos = parseIPaddress (newRule->ipaddr2, pos+1);
        if ((pos == NULL) || (newRule->ipaddr2[0] == -1)) {
            free (newRule);
            return NULL;
        }
        
        if (compareIPAddresses (newRule->ipaddr1, newRule->ipaddr2) != -1) {
            free(newRule);
            return NULL;
	    }
    }
    else {
	    newRule->ipaddr2[0] = -1;
    }
    if (*pos != ' ') {
        free(newRule);
        return NULL;
    }
    else pos++;

    // parse ports
    pos = parsePort (&(newRule->port1), pos);
    if ((pos == NULL) || (newRule->port1 == -1)) {
        free(newRule);
        return NULL;
    }
    if ((*pos == '\n') || (*pos == '\0')) {
        newRule->port2 = -1;
        return newRule;
    }
    if (*pos != '-') {
        free(newRule);
        return NULL;
    }
    
    pos++;
    pos = parsePort (&(newRule->port2), pos);
    if ((pos == NULL) || (newRule->port2 == -1)) {
        free(newRule);
        return NULL;
    }
    if (newRule->port2 <= newRule->port1) {
        free(newRule);
        return NULL;
    }
    if ((*pos == '\n') || (*pos == '\0')) {
	    return newRule;
    }
    free(newRule);
    return NULL;
}

struct ruleErrors_t *allErrors = NULL;

struct ruleErrors_t *addErrorRule (struct ruleErrors_t *errors, char * line) {
    struct ruleErrors_t *newError;

    newError = malloc(sizeof(struct ruleErrors_t));
    newError->line = line;
    newError->next = errors;
    return newError;
}

// Addind a new rule to the existing set of firewall rules
struct firewallRules_t * addRule (struct firewallRules_t * rules, struct firewallRule_t *rule) {
    struct firewallRules_t *newRule;

    newRule = malloc(sizeof(struct firewallRules_t));
    newRule->rule = rule;
    // Pointing to the head of the existing set of firewall rules
    newRule->next = rules;
    return newRule;
}

struct firewallQuery * addQuery (struct firewallRule_t *rule, struct firewallRule_t *checkRule) {
    struct firewallQuery *newQuery;

    newQuery = malloc(sizeof(struct firewallQuery));
    sprintf(newQuery->query, "%d.%d.%d.%d %d", checkRule->ipaddr1[0], checkRule->ipaddr1[1],checkRule->ipaddr1[2],checkRule->ipaddr1[3],checkRule->port1);

    // Pointing to the head of the existing set of firewall rules
    newQuery->next = rule->queryList;
    return newQuery;
}
    
	
/*struct firewallRules_t *readFile (char *filename) {
    FILE *file;
    int result;
    char *line = NULL;

    size_t lineSize;
    
    struct firewallRule_t *newRule;
    char *errorLine;
    struct firewallRules_t * allRules = NULL;
    int noOfRules = 0;

    file = fopen (filename, "r");

    if (file == NULL) {
        fprintf (stderr, "Could not open file, exiting!\n");
        exit (1);
    }

    while ((result = getline(&line, &lineSize, file)) != -1) {
        newRule = readRule(line);
	if (newRule == NULL) {
	    errorLine = malloc(lineSize+1);
	    strcpy(errorLine, line);
	    allErrors = addErrorRule(allErrors, errorLine);
	}
	else {
        // [] -> []-> []_-> [] -> [] -> NULL
	    allRules = addRule(allRules, newRule);
	    noOfRules++;
	}
    }
    free(line);
    fclose(file);
    allRules = sortRules(allRules, noOfRules);
    return allRules;
} */
/* displays error messages from system calls */
void error(char *msg)
{
    perror(msg);
    exit(1);
};

struct threadArgs_t {
    int newsockfd;
    int threadIndex;
};
      

int isExecuted = 0;
int returnValue = 0; /* not used; need something to keep compiler happy */
pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER; /* the lock used for processing */

/* this is only necessary for proper termination of threads - you should not need to access this part in your code */
struct threadInfo_t {
    pthread_t pthreadInfo;
    pthread_attr_t attributes;
    int status;
};
struct threadInfo_t *serverThreads = NULL;
int noOfThreads = 0;
pthread_rwlock_t threadLock =  PTHREAD_RWLOCK_INITIALIZER;
pthread_cond_t threadCond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t threadEndLock = PTHREAD_MUTEX_INITIALIZER;

void freeQueries(struct firewallQuery *query) {
    struct firewallQuery *currentQuery = query;
    struct firewallQuery *nextQuery;

    while (currentQuery != NULL) {
        nextQuery = currentQuery->next;
        free(currentQuery);
        currentQuery = nextQuery;
    }
}

void freeRule(struct firewallRule_t *rule) {
    freeQueries(rule->queryList);
    free(rule);
}




// Function to compare two rules
int comparingRules(struct firewallRule_t *rule1, struct firewallRule_t *rule2){
    if(rule1->ipaddr2[0] == -1 && rule2->ipaddr2[0] == -1){
      for(int i = 0; i < 4; i++){
        if(rule1->ipaddr1[i] != rule2->ipaddr1[i]){
          return 0;
        }
      }
      if(rule1->port1 != rule2->port1){
        return 0;
      }

    }else if (rule1->ipaddr2[0] != -1 && rule2->ipaddr2[0] != -1)
    {
      for(int i = 0; i < 4; i++){
        if(rule1->ipaddr1[i] != rule2->ipaddr1[i]){
        return 0;
        }
      }
      for(int i = 0; i < 4; i++){
        if(rule1->ipaddr2[i] != rule2->ipaddr2[i]){
          return 0;
        }
      }
      if(rule1->port1 != rule2->port1){
        return 0;
      }
      if(rule1->port2 != rule2->port2){
        return 0;
      }
    }
    return 1;
}



int deleteRule(struct firewallRules_t **rules, struct firewallRule_t *ruleToDelete) {
    if (*rules == NULL || ruleToDelete == NULL) {
        return 0;
    }

    struct firewallRules_t *currentRule = *rules;
    struct firewallRules_t *prevRule = NULL;

    while (currentRule != NULL) {
        if (comparingRules(currentRule->rule, ruleToDelete) == 1) {
            if (prevRule == NULL) {
                *rules = currentRule->next; // Update head if deleting the first rule
            } else {
                prevRule->next = currentRule->next;
            }
            free(currentRule); // Free the firewallRules_t node

            return 1;
        }

        prevRule = currentRule;
        currentRule = currentRule->next;
    }

    return 0;
}














int identicalrules(struct firewallRule_t * rule, struct firewallRule_t *checkRule){
    for(int i = 0; i < 4; i++){
      if(rule->ipaddr1[i] != checkRule->ipaddr1[i]){
        return 0;
      }
    }
    if(rule->port1 != checkRule->port1){
      return 0;
    }

    return 1;
}

int checkInRange(struct firewallRule_t * rule, struct firewallRule_t *checkRule){

    for(int i = 0; i < 4; i++){
      printf("%d\n", i);
      if(checkRule->ipaddr1[i] < rule->ipaddr1[i] || checkRule->ipaddr1[i] > rule->ipaddr2[i]){
        return 0;
      }
    }if(checkRule->port1 < rule->port1 || checkRule->port1 > rule->port2){
      return 0;
    }

    return 1;
}

int checkAllowance(struct firewallRule_t * rule, struct firewallRule_t *checkRule){
  if((rule->ipaddr2[0] == -1 && identicalrules(rule, checkRule) == 1) || (rule->ipaddr2[0] != -1 && checkInRange(rule, checkRule) == 1)){
      rule->queryList = addQuery(rule,checkRule);
      return 1;
  }
  return 0;
}

int checkExecution(struct firewallRules_t * rules, struct firewallRule_t *rule){
  struct firewallRules_t *currentNode= rules;
  int i = 0;

  while(currentNode != NULL){
    i = checkAllowance(currentNode->rule, rule);
    if(i == 1){
      return i;
    }
    currentNode= currentNode->next;
  }
  return i;
}









void getFirewallRules(struct firewallRules_t *rules, char *buffer) {
    buffer[0] = '\0';  // Ensure the buffer is initially empty

    while (rules != NULL) {

        sprintf(buffer + strlen(buffer), "Rule: %d.%d.%d.%d", rules->rule->ipaddr1[0], rules->rule->ipaddr1[1],rules->rule->ipaddr1[2], rules->rule->ipaddr1[3]);

        if (rules->rule->ipaddr2[0] != -1) {
          sprintf(buffer + strlen(buffer), "-%d.%d.%d.%d", rules->rule->ipaddr2[0], rules->rule->ipaddr2[1],rules->rule->ipaddr2[2], rules->rule->ipaddr2[3]);
        }

        sprintf(buffer + strlen(buffer), " %d", rules->rule->port1);

        if (rules->rule->port2 != -1) {
            sprintf(buffer + strlen(buffer), "-%d", rules->rule->port2);
        }

        sprintf(buffer + strlen(buffer), "\n");

        struct firewallQuery *queryNode = rules->rule->queryList;
        while (queryNode != NULL) {
            sprintf(buffer + strlen(buffer), "Query: %s\n", queryNode->query);
            queryNode = queryNode->next;
        }

        rules = rules->next;
    }

}



/* For each connection, this function is called in a separate thread. You need to modify this function. */
void *processRequest (void *args) {
  struct threadArgs_t *threadArgs;
  char buffer[MAX_BUFFER];
  int n;


  struct firewallRule_t *newRule1;
  newRule1 = malloc(sizeof(struct firewallRule_t));    

  struct firewallRule_t *newRule2;
  newRule2 = malloc(sizeof(struct firewallRule_t));
  
  struct firewallRule_t *newRule3;
  newRule3 = malloc(sizeof(struct firewallRule_t));

  threadArgs = (struct threadArgs_t *) args;
  bzero (buffer, BUFFERLENGTH);
  n = read (threadArgs->newsockfd, buffer, BUFFERLENGTH -1);
  if (n < 0){
    error ("ERROR reading from socket");
  }

    pthread_mutex_lock (&mut); /* lock exclusive access to variable isExecuted */
    
    if(buffer[0] == 'A'){
      char *start = strstr(buffer, " ");
      start = start + 1;
      n = sprintf(buffer, "%s", start);
      newRule1 = readRule(buffer, newRule1);
      if(newRule1 != NULL){
          allRules = addRule(allRules, newRule1);
          noOfRules = noOfRules + 1;
          n = sprintf(buffer, "Rule added.");
          n = write(threadArgs->newsockfd, buffer, BUFFERLENGTH);
          if(n < 0){
              error("Error Writing");
          }
      }else{
          n = sprintf(buffer, "Invalid rule.");
          n = write(threadArgs->newsockfd, buffer, BUFFERLENGTH);
          if(n < 0){
              error("Error Writing");
          }
      
      }
  }
  else if (buffer[0] == 'C'){
      int check = 0;
      char *start = strstr(buffer, " ");
      start = start + 1;
      n = sprintf(buffer, "%s", start); 
      newRule2 = readRule(buffer, newRule2);

      if(newRule2 != NULL){
          check = checkExecution(allRules, newRule2);
          if(check == 1){
            n = sprintf(buffer, "Connection accepted.\n");
          }else{
            n = sprintf(buffer, "Connection rejected.\n");
          }
           n = write(threadArgs->newsockfd, buffer, BUFFERLENGTH);

      }else{
         n = sprintf(buffer, "Invalid IP address or port specified.\n");
         n = write(threadArgs->newsockfd, buffer, BUFFERLENGTH);
        if(n < 0){
            error("Error Writing");
        }
      }

  }else if (buffer[0] == 'D'){
    char *start = strstr(buffer, " ");
    start = start + 1;
    n = sprintf(buffer, "%s", start);   
    newRule3 = readRule(buffer, newRule3);
    if(newRule3 != NULL){
      n = sprintf(buffer,"%d\n", deleteRule(&allRules, newRule3));
      if(strcmp(buffer, "1") == 0){
        n = sprintf(buffer,"Rule not found.\n");
        noOfRules = noOfRules - 1;
      }else{
        n = sprintf(buffer,"Rule  not deleted.\n");
      }
      n = write(threadArgs->newsockfd, buffer, BUFFERLENGTH);
      if(n < 0){
        error("Error Writing");
    } 
    }else{
        n = sprintf(buffer, "Rule Invalid.\n");
        n = write(threadArgs->newsockfd, buffer, BUFFERLENGTH);
        if(n < 0){
            error("Error Writing");
        }   
    }
  }else if (buffer[0] == 'L'){
      getFirewallRules(allRules, buffer);
      n = write(threadArgs->newsockfd, buffer, BUFFERLENGTH);
      if(n < 0){
        error("Error writing");
      }
}else{
  n = sprintf(buffer, "Illegale Request.\n");
  n = write(threadArgs->newsockfd, buffer, BUFFERLENGTH);
  if(n < 0){
    error("Error Writing");
 }   
}

    

    pthread_mutex_unlock (&mut); /* release the lock */
    n = sprintf (buffer, "I got you message, the  value of isExecuted is %d\n", isExecuted);
    n = write (threadArgs->newsockfd, buffer, BUFFERLENGTH);
    if (n < 0) 
      error ("ERROR writing to socket");
       
  /* these two lines are required for proper thread termination */
    serverThreads[threadArgs->threadIndex].status = THREAD_FINISHED;
    pthread_cond_signal(&threadCond);
  
    close (threadArgs->newsockfd); /* important to avoid memory leak */  
    free (threadArgs);
    pthread_exit (&returnValue);
}

/* finds unused thread info slot; allocates more slots if necessary
   only called by main thread */
int findThreadIndex () {
    int i, tmp;

    for (i = 0; i < noOfThreads; i++) {
	if (serverThreads[i].status == THREAD_AVAILABLE) {
	    serverThreads[i].status = THREAD_IN_USE;
	    return i;
	}
    }

    /* no available thread found; need to allocate more threads */
    pthread_rwlock_wrlock (&threadLock);
    serverThreads = realloc(serverThreads, ((noOfThreads + THREADS_ALLOCATED) * sizeof(struct threadInfo_t)));
    noOfThreads = noOfThreads + THREADS_ALLOCATED;
    pthread_rwlock_unlock (&threadLock);
    if (serverThreads == NULL) {
    	fprintf (stderr, "Memory allocation failed\n");
	exit (1);
    }
    /* initialise thread status */
    for (tmp = i+1; tmp < noOfThreads; tmp++) {
	serverThreads[tmp].status = THREAD_AVAILABLE;
    }
    serverThreads[i].status = THREAD_IN_USE;
    return i;
}

/* waits for threads to finish and releases resources used by the thread management functions. You don't need to modify this function */
void *waitForThreads(void *args) {
    int i, res;
    while (1) {
	pthread_mutex_lock(&threadEndLock);
	pthread_cond_wait(&threadCond, &threadEndLock);
	pthread_mutex_unlock(&threadEndLock);

	pthread_rwlock_rdlock(&threadLock);
	for (i = 0; i < noOfThreads; i++) {
	    if (serverThreads[i].status == THREAD_FINISHED) {
		res = pthread_join (serverThreads[i].pthreadInfo, NULL);
		if (res != 0) {
		    fprintf (stderr, "thread joining failed, exiting\n");
		    exit (1);
		}
		serverThreads[i].status = THREAD_AVAILABLE;
	    }
	}
	pthread_rwlock_unlock(&threadLock);
    }
}

int main(int argc, char **argv)
{
     socklen_t clilen;
     int sockfd, portno;
     struct sockaddr_in6 serv_addr, cli_addr;
     int result;
     pthread_t waitInfo;
     pthread_attr_t waitAttributes;

     if (argc < 2) {
         fprintf (stderr,"ERROR, no port provided\n");
         exit(1);
     }
     
     /* create socket */
     sockfd = socket (AF_INET6, SOCK_STREAM, 0);
     if (sockfd < 0) 
        error("ERROR opening socket");
     bzero ((char *) &serv_addr, sizeof(serv_addr));
     portno = atoi(argv[1]);
     serv_addr.sin6_family = AF_INET6;
     serv_addr.sin6_addr = in6addr_any;
     serv_addr.sin6_port = htons (portno);

     /* bind it */
     if (bind(sockfd, (struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) error("ERROR on binding");

     /* ready to accept connections */
     listen (sockfd,5);
     clilen = sizeof (cli_addr);
     
       /* create separate thread for waiting  for other threads to finish */
     if (pthread_attr_init (&waitAttributes)) {
        fprintf (stderr, "Creating initial thread attributes failed!\n");
	      exit (1);
     }

     result = pthread_create (&waitInfo, &waitAttributes, waitForThreads, NULL);
    if (result != 0) {
	      fprintf (stderr, "Initial Thread creation failed!\n");
	      exit (1);
      }


     /* now wait in an endless loop for connections and process them */
       while(1) { 
	        struct threadArgs_t *threadArgs; /* must be allocated on the heap to prevent variable going out of scope */
	        int threadIndex;

          threadArgs = malloc(sizeof(struct threadArgs_t));
          if (!threadArgs) {
	          fprintf (stderr, "Memory allocation failed!\n");
	          exit (1);
         }

       /* waiting for connections */
       threadArgs->newsockfd = accept( sockfd, 
			  (struct sockaddr *) &cli_addr, 
			  &clilen);
       if (threadArgs->newsockfd < 0) 
	 error ("ERROR on accept");

       /* create thread for processing of connection */
       threadIndex =findThreadIndex();
       threadArgs->threadIndex = threadIndex;
       if (pthread_attr_init (&(serverThreads[threadIndex].attributes))) {
	       fprintf (stderr, "Creating thread attributes failed!\n");
	      exit (1);
     }
       
       
       result = pthread_create (&(serverThreads[threadIndex].pthreadInfo), &(serverThreads[threadIndex].attributes), processRequest, (void *) threadArgs);
       if (result != 0) {
	 fprintf (stderr, "Thread creation failed!\n");
	 exit (1);
       }

       
     }
}





