#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/param.h>
#include <string.h>
#include <ldap.h>

#define LDAP_SERVER "ldap.supinfo.local"
#define BASE_DN "dc=supinfo,dc=local"

int main (int argc, char const *argv[])
{
	/* code */
	char hostname[MAXHOSTNAMELEN], *attrs[2], **vals;
	LDAP *ldap;
	LDAPMessage *results = NULL, *entry = NULL;
	int haveGpoDescriptor = 0;
	
	int ret, version, i;
	
	
	printf("----------------------------------\n");
	printf("Getting host informations...\n");
	printf("----------------------------------\n\n");	
	
	if(gethostname(hostname,MAXHOSTNAMELEN) == 0){
		struct hostent * record = gethostbyname(hostname);
		struct in_addr * address = ( struct in_addr *) record->h_addr;
		printf("Hostname: %s\n", hostname);
		printf("FQDN: %s\n", record->h_name);
		printf("IP Address: %s\n", inet_ntoa(address->s_addr));

		printf("\n\n----------------------------------\n");
		printf("Connecting to %s\n",LDAP_SERVER);
		printf("----------------------------------\n\n");
		
		ldap = (LDAP*) ldap_open(LDAP_SERVER,LDAP_PORT);
		
		if(!ldap){
			printf("Unable to connect to the LDAP Server\n");
			return 1;
			}else{
				version = LDAP_VERSION3;
				ldap_set_option( ldap, LDAP_OPT_PROTOCOL_VERSION, &version );
				
				printf("Connected to LDAP server: \033[32;mOk\033[00m.\n");
				
				printf("\n\n----------------------------------\n");
				printf("Binding...\n");
				printf("----------------------------------\n\n");
				
				/* Anonymous binding... Les machines n'ont pas de mot de passe*/
				ret = ldap_simple_bind_s(ldap, NULL, NULL);
				if (ret != LDAP_SUCCESS) {
					printf("Binding \033[31;mFailed\033[00m\n\n");
					char *error;
					ldap_perror(ldap,error);
					printf("%s",error);
					return 1;
				}
				
				printf("Binding: \033[32;mOk\033[00m.\n");
				
				printf("\n\n----------------------------------\n");
				printf("Searching for workstation %s in %s\n",hostname, BASE_DN);
				printf("----------------------------------\n\n");
				
				char context[MAXHOSTNAMELEN + 5];				
				snprintf(context,MAXHOSTNAMELEN + 5, "(cn=%s)",hostname);
								
				ret = ldap_search_s(
					ldap,
					BASE_DN,
					LDAP_SCOPE_SUBTREE,
					context,
					NULL,
					0,
					&results);
				
				if(ret != LDAP_SUCCESS){
					printf("Unable to perform search\n");
					char *error;
					ldap_perror(ldap,error);
					printf("%s",error);					
				}
				
				entry = ldap_first_entry(ldap, results);
				if (!entry) {
					printf("\033[33;m%s workstation not found !\033[00m\n", hostname);
					return 1;
				}else{
					printf("\033[33;m%s workstation found !\033[00m\n", hostname);
				}
				
				printf("\n\n----------------------------------\n");
				printf("Getting OU container name of %s\n",context);
				printf("----------------------------------\n\n");
				
				vals = (char**) ldap_get_values(ldap,entry,"ou");
				char *ou = NULL;
				for(i=0;vals[i] != NULL;i++){
					ou = vals[i];
					printf("\033[33;mOU [%d] name of %s: %s\033[00m\n",i,context,vals[i]);
					break;
				}
				
				printf("\n\n----------------------------------\n");
				printf("Searching groupPolicyDescriptor into OU container name: %s of %s\n",ou,context);
				printf("----------------------------------\n\n");
				
				
				vals = (char**) ldap_get_values(ldap,entry,"objectClass");

				for(i=0;vals[i] != NULL;i++){
					if (strcmp(vals[i],"groupPolicyDescriptor") ) {
						haveGpoDescriptor = 1;
						printf("\033[33;mGPO Found !\033[00m\n");
						char **uri = ldap_get_values(ldap,entry,"uri");
						printf("\033[33;mScript path: %s !\033[00m\n",uri[0]);
						// system("/bin/sh -c %s"); %s = uri[0]
						break;
					}
				}
				
				
				printf("\n\n----------------------------------\n");
				printf("Cleaning memory\n");
				printf("----------------------------------\n\n");
				
				ldap_value_free(vals);
				ldap_msgfree(entry);
				ldap_unbind(ldap);
			}
		
	}else{
		printf("Cannot get the hostname.\n");
	}	
	
	return 0;
}
