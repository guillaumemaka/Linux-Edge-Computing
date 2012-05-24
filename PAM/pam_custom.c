#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/param.h>
#include <string.h>
#include <ldap.h>

#define LDAP_SERVER "ldap.supinfo.local"
#define BASE_DN "dc=supinfo,dc=local"

static struct pam_conv conv = {misc_conv, NULL};

int main (int argc, char const *argv[])
{
	/* code */
	
	pam_handle_t *pamh = NULL;
	char *user, *password , **userVals = NULL, **ouVals = NULL, **uriVals = NULL, *context;
	LDAP *ldap = NULL;
	LDAPMessage *userResults = NULL,*ouResults = NULL, *userEntry = NULL, *ouEntry = NULL;
	//bool haveGpoDescriptor = 0;
	
	user = getlogin();

	int pamretval, ret, version, i = 0 ,j = 0, k = 0;
	
	printf("----------------------------------\n");
	printf("Getting session informations...\n");
	printf("----------------------------------\n\n");	

	pamretval = pam_start("custom",user,&conv,&pamh);
	
	if(pamretval == PAM_SUCCESS ){
		/*
		TODO:
		-------------------------------------------------------------
		Si pam_start(...) renvoie PAM_SUCCESS alors
		récuperer:
			- username 
			- password			
		*/
				
		printf("Logged as: \033[32;m%s\033[00m.\n",user);
			
		printf("\n\n----------------------------------\n");
		printf("Connecting to %s\n",LDAP_SERVER);
		printf("----------------------------------\n\n");
		
		ldap = (LDAP*) ldap_open(LDAP_SERVER,LDAP_PORT);
		
		if(!ldap){
			printf("Unable to connect to the LDAP Server\n");
				return PAM_SUCCESS; // Don't break the PAM Stack
			}else{
				version = LDAP_VERSION3;
				ldap_set_option( ldap, LDAP_OPT_PROTOCOL_VERSION, &version );
				
				printf("Connected to LDAP server: \033[32;mOk\033[00m.\n");
				
				printf("\n\n----------------------------------\n");
				printf("Binding...\n");
				printf("----------------------------------\n\n");
				
				/*	Anonymous Binding */				
	
				ret = ldap_simple_bind_s(ldap, NULL, NULL);
				if (ret != LDAP_SUCCESS) {
					printf("Binding \033[31;mFailed\033[00m\n\n");
					char *error;
					ldap_perror(ldap,error);
					printf("%s",error);
					return PAM_SUCCESS;
				}
				
				printf("Binding: \033[32;mOk\033[00m.\n");
				
				/*
				TODO <Version compliquée>
				--------------------------------------------------
				Note:
				Créer autant de LDAPMessage *results qu'il ya de recherche à faire				
				ldap_get_values return char** (un tableau/array)
				context = (cn | ou = <username | ou_name)
				------
				
				1. Récupérer l'utilisateur 
					-> ldap_search_s(ldap,BASE_DN,LDAP_SCOPE_SUBTREE,context,NULL,0,&userResults); context = (cn=username)
					-> userEntry = ldap_get_first_entry(ldap,userResults);
				2. Récupérer le nom de l'OU (OrganizationalUnit) de l'utilisateur 
					-> char ou_name =  ldap_get_values(ldap,userEntry,"ou")					
				3. Récupérer l'OU en faisant une nouvelle recherche 
					-> ldap_search_s(ldap,BASE_DN,LDAP_SCOPE_SUBTREE,context,NULL,0,&ouResults); context = (ou=ou_name)
					-> ouEntry = ldap_get_first_entry(ldap,ouResults);
				4. Chercher l'objectClass groupPolicyDescriptor dans l'OU de l'étape précédente
					- char **vals = ldap_get_values(ldap,ouEntry,"objectClass")
					NB: Un objet LDAP peut avoir plusieur objectClass
					for(i=0 ; vals[i] != NULL;i++){
						if(strcmp(vals[i], "groupPolicyDescriptor")){
							
							4.1 Récuperer l'attribut "uri"
							char **vals = ldap_get_values(ldap,ouEntry,"uri");
							// action 
							system("/bin/sh <uri>")							
						}
					}
									
				*/
				
				context = calloc(sizeof(char),strlen(user)+29);
				sprintf(context,"(&(cn=%s)(objectClass=account))",user);
								
				
				// 1. Récupérer l'utilisateur 
				ret = ldap_search_s(ldap,BASE_DN,LDAP_SCOPE_SUBTREE,context,NULL,0,&userResults);
				userEntry = ldap_first_entry(ldap,userResults);					
								
				if(userEntry){
					// 2. Récupérer le(s) nom(s) de(s) l'OU (OrganizationalUnit) de l'utilisateur 					
					userVals = (char**) ldap_get_values(ldap,userEntry,"ou");
					
					for (i = 0 ; userVals[i] != NULL ; i++ ){
						
						context = calloc(sizeof(char),strlen(userVals[i])+40);
						sprintf(context,"(&(ou=%s)(objectClass=organizationalUnit))",userVals[i]);
						
						// 3. Récupérer l'OU en faisant une nouvelle recherche 
						ret = ldap_search_s(ldap,BASE_DN,LDAP_SCOPE_SUBTREE,context,NULL,0,	&ouResults);
						ouEntry = ldap_first_entry(ldap,ouResults);					
						
						if (ouEntry){
							printf("\033[33;m\nFound OU %s ... \033[00m\n", userVals[i]);
							printf("\033[33;m\nSearching GPO in ou=%s ... \033[00m\n", userVals[i]);
							ouVals = (char **) ldap_get_values(ldap,ouEntry,"objectClass");
							
							for ( j = 0 ; ouVals[j] != NULL ; j++ ){
								
								// 4. Chercher l'objectClass groupPolicyDescriptor dans l'OU
																
								if(strcmp(ouVals[j],"groupPolicyDescriptor") == 0){
									
									// 4.1 Récuperer l'attribut "uri"
									
									uriVals = (char **) ldap_get_values(ldap,ouEntry,"uri");
									printf("\033[33;mGPO Found in ou=%s \033[00m\n", userVals[i]);
																									
									for ( k = 0 ; uriVals[k] != NULL ; k++) {
										printf("\033[33;mURI Script: %s\033[00m\n", uriVals[k]);
									}
								}
							}
						} else {	printf("\033[33;m\nNo OU found for user: %s \033[00m\n", user )	;}	
					}
				} else {	printf("\033[33;m\nUser %s not found in LDAP Directory \033[00m\n", user);	}	
					
				printf("\n\n----------------------------------\n");
				printf("Cleaning memory\n");
				printf("----------------------------------\n\n");
				
				if(userVals) ldap_value_free(userVals);
				if(ouVals) ldap_value_free(ouVals);
				if(uriVals) ldap_value_free(uriVals);
				if(ouEntry) ldap_msgfree(ouEntry);
				if(userEntry) ldap_msgfree(userEntry);
				ldap_unbind(ldap);
			}
		
		pam_end(pamh,pamretval);
		
		return PAM_SUCCESS;
	}else{
		printf("User not logged in.\n");
		return PAM_USER_UNKNOWN;
	}	
}
