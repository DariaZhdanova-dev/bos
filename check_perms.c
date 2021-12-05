#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <stdio.h>      
#include <stdlib.h>              
#include <unistd.h>     
#include <errno.h>      
#include <string.h>     
#include <stdbool.h>    
#include <acl/libacl.h>
#include <sys/acl.h>
#include <sys/stat.h>
#include <selinux/selinux.h>

#define ACCESS_ALLOW 0
#define ACCESS_DENY 1

#define DAC_READ = 1
#define DAC_WRITE = 2
#define DAC_EXECUTE = 3

int handleError(char *, int);
void printPerms (acl_permset_t);

char* userNameFromId(uid_t uid)
{
    struct passwd *pwd;

    pwd = getpwuid(uid);
    return (pwd == NULL) ? NULL : pwd->pw_name;
}

uid_t userIdFromName(const char *name)
{
    struct passwd *pwd;
    uid_t u;
    char *endptr;

    if (name == NULL || *name == '\0')
        return -1;

    u = strtol(name, &endptr, 10);
    if (*endptr == '\0')
        return u;

    pwd = getpwnam(name);
    if (pwd == NULL)
        return -1;

    return pwd->pw_uid;
}

char* groupNameFromId(gid_t gid)
{
    struct group *grp;

    grp = getgrgid(gid);
    return (grp == NULL) ? NULL : grp->gr_name;
}

gid_t groupIdFromName(const char *name)
{
    struct group *grp;
    gid_t g;
    char *endptr;

    if (name == NULL || *name == '\0')
        return -1;

    g = strtol(name, &endptr, 10);
    if (*endptr == '\0')
        return g;

    grp = getgrnam(name);
    if (grp == NULL)
        return -1;

    return grp->gr_gid;
}

//int CheckDacPermission(const char* file, 
//                       const uid_t proc_uid, 
//                       const gid_t proc_gid,
//                       const uid_t file_uid, 
//                       const gid_t file_gid,
//                       const int perm_to_check)
//{
//	if (perm_to_check != DAC_READ && perm_to_check != DAC_WRITE && perm_to_check != DAC_EXECUTE)
//		{ printf("%s\n", "Error: DAC unknown permission"); exit(1); }
//    struct stat st;
//    int res = 0;
//    char* modeval = (char*)malloc(sizeof(char) * 9 + 1);
//    if(stat(file, &st) == 0)
//    {
//        mode_t perm = st.st_mode;
//        modeval[0] = (perm & S_IRUSR) ? 'r' : '-';
//        modeval[1] = (perm & S_IWUSR) ? 'w' : '-';
//        modeval[2] = (perm & S_IXUSR) ? 'x' : '-';
//        modeval[3] = (perm & S_IRGRP) ? 'r' : '-';
//        modeval[4] = (perm & S_IWGRP) ? 'w' : '-';
//        modeval[5] = (perm & S_IXGRP) ? 'x' : '-';
//        modeval[6] = (perm & S_IROTH) ? 'r' : '-';
//        modeval[7] = (perm & S_IWOTH) ? 'w' : '-';
//        modeval[8] = (perm & S_IXOTH) ? 'x' : '-';
//        modeval[9] = '\0';
//        return modeval;     
//    }
//    else
//    {
//        printf("%s\n", "Error: stat"); exit(1);
//    }
//    
//	printf("DAC permissions: %s", modeval);
//    if (proc_uid == file_uid)
//		res = modeval[perm_to_check] != '-' ? ACCESS_ALLOW : ACCESS_DENY;
//	else if (proc_gid == file_gid)
//		res =  modeval[2 + perm_to_check] != '-' ? ACCESS_ALLOW : ACCESS_DENY;
//	else
//		res = modeval[5 + perm_to_check] != '-' ? ACCESS_ALLOW : ACCESS_DENY;
//	
//	free(modeval);
//	return res;
//}

int MaskPermset (acl_permset_t* perms, acl_permset_t mask) {
	int a;
	
	a = acl_get_perm(mask, ACL_READ);
	if (a == -1) { return -1; }
	if (a == 0) {
		if (acl_delete_perm(*perms, ACL_READ) == -1) {
		return -1;
		}
	}
	
	a = acl_get_perm(mask, ACL_WRITE);
	if (a == -1) { return -1; }
	if (a == 0) {
		if (acl_delete_perm(*perms, ACL_WRITE) == -1) {
		return -1;
		}
	}
	
	a = acl_get_perm(mask, ACL_EXECUTE);
	if (a == -1) { return -1; }
	if (a == 0) {
		if (acl_delete_perm(*perms, ACL_EXECUTE) == -1) {
		return -1;
		}
	}
	
	return 0;
}

int handleError(char *str, int a) 
{
	if (a == -1) { printf("Error: %s\n", str); exit(1); }
	
	return a;
}

void printPerms (acl_permset_t permset) {
	printf(
		"%c%c%c",
		(handleError("acl_get_perm", acl_get_perm(permset, ACL_READ))    ? 'r' : '-'),
		(handleError("acl_get_perm", acl_get_perm(permset, ACL_WRITE))   ? 'w' : '-'),
		(handleError("acl_get_perm", acl_get_perm(permset, ACL_EXECUTE)) ? 'x' : '-')
	);
}

int CheckAclPermission(const char* filename, 
			const uid_t proc_uid, 
                       const gid_t proc_gid,
                       const int perm_to_check)
{
	printf("%s\n", "Computing access with ACL...");

	char mode = 'u';
	
	if (perm_to_check != ACL_READ && perm_to_check != ACL_WRITE && perm_to_check != ACL_EXECUTE)
			{ printf("%s\n", "Error: unknown permission"); exit(1); }
	
	if (proc_uid == -1) { printf("Error: %s\n", "no proc_uid" ); exit(1); }
	
	const char *filepath = filename;
	struct stat stats;
	
	if (stat(filepath, &stats) == -1) { printf("Error: %s\n", "stat" ); exit(1); }
	
	acl_t acl = acl_get_file(filepath, ACL_TYPE_ACCESS);
	if (acl == NULL) { printf("Error: %s\n", "acl_get_file" ); exit(1); }
	
	acl_entry_t entry;
	acl_tag_t tag;
	int entryId;
	
	int mask_found = 0;
	acl_entry_t mask;
	for (entryId = ACL_FIRST_ENTRY; ; entryId = ACL_NEXT_ENTRY) {
		if (acl_get_entry(acl, entryId, &entry) == 1) {
			break;
		}
		if ((tag = acl_get_tag_type(entry, &tag)) == -1) { printf("Error: %s\n", "acl_get_tag_type" ); exit(1); }
		if (tag == ACL_MASK) {
			mask_found = 1;
			mask = entry;
			break;
		}
	}
	
	acl_entry_t needle;
	uid_t *uid_p;
	//gid_t *gid_p;
	
	for (entryId = ACL_FIRST_ENTRY; ; entryId = ACL_NEXT_ENTRY) {
		if (acl_get_entry(acl, entryId, &entry) != 1) { printf("Error: %s\n", "acl_get_entry" ); exit(1); }
		if (acl_get_tag_type(entry, &tag) == -1) { printf("Error: %s\n", "acl_get_tag_type" ); exit(1); }
	
		if (mode == 'u') 
		{
			if (proc_uid == stats.st_uid && tag == ACL_USER_OBJ) 
			{
				needle = entry;
				break;
			}
			if (tag != ACL_USER) { continue; }
			uid_p = acl_get_qualifier(entry);
			if (uid_p == NULL) { printf("Error: %s\n", "acl_get_qualifier" ); exit(1); }
			if (*uid_p == proc_uid) 
			{
				needle = entry;
				break;
			}
		}
	
		//if (mode == 'g') {
		//	if (gid == stats.st_gid && tag == ACL_GROUP_OBJ) 
		//	{
		//		needle = entry;
		//		break;
		//	}
		//	if (tag != ACL_GROUP) { continue; }
		//	gid_p = acl_get_qualifier(entry);
		//	if (gid_p == NULL) { printf("Error: %s\n", "acl_get_qualifier" ); exit(1); }
		//	if (*gid_p == gid) 
		//	{
		//		needle = entry;
		//		break;
		//	}
		//}
	}
	
	acl_permset_t needle_perms;
	if (acl_get_permset(needle, &needle_perms) == -1) { printf("Error: %s\n", "acl_get_permset" ); exit(1); }
	printf("%s", "ACL permissions: ");
	printPerms(needle_perms);
	printf("\n");
	if (mask_found && !(mode == 'u' && proc_uid == stats.st_uid && tag == ACL_USER_OBJ)) {
		acl_permset_t mask_perms;
		if (acl_get_permset(mask, &mask_perms) == -1) { printf("Error: %s\n", "acl_get_permset" ); exit(1); }
		printf("%s", "ACL effective permissions: ");
		if (MaskPermset(&needle_perms, mask_perms) == -1) { printf("Error: %s\n", "maskPermset" ); exit(1); }
		printPerms(needle_perms);
		printf("\n");
	}
	int permVal = acl_get_perm(needle_perms, perm_to_check);
	if (permVal == -1) { printf("%s\n", "Error: acl_get_perm"); exit(1); }
	if (permVal == 1) 
	{ 
		acl_free(acl); 
		printf("%s\n", "ACL: access allowed");
		return ACCESS_ALLOW; 
	}
	else 
	{ 
		acl_free(acl); 
		printf("%s\n", "ACL: access denied");
		return ACCESS_DENY; 
	}
}

int CheckSeLinuxPermission(const char *path, const char *perm)
{
	printf("%s\n", "Computing access with SELinux...");

	char *scon = NULL, *tcon = NULL;
	const char *tclass = "file";
	int allowed = -1;
	
	if (getcon(&scon) < 0) {
		printf("%s\n", "Error: getcon");
		goto out;
	}
	
	if (getfilecon(path, &tcon) < 0) {
		printf("%s\n", "Error: getfilecon");
		goto out;
	}
	
	allowed = selinux_check_access(scon, tcon, tclass, perm, NULL);

out:
	freecon(scon);
	freecon(tcon);
	
	if (!allowed) 
	{
		printf("%s\n", "SELinux: access allowed");
		return ACCESS_ALLOW;
	}
	printf("%s\n", "SELinux: access denied");
	return ACCESS_DENY;
}

int main(int argc, char* argv[])
{
	if (argc != 3)
	{
		printf("%s\n", "Wrong arguments");
		return 0;
	}
	
	const char* path = argv[1];
	const char* perm = argv[2];
	uid_t uid = 0;
	gid_t gid = 0;
	int allowed = ACCESS_DENY;
	
	if (!strcmp(perm, "create") ||
		!strcmp(perm, "getattr") ||
		!strcmp(perm, "rename") ||
		!strcmp(perm, "read") ||
		!strcmp(perm, "write") ||
		!strcmp(perm, "execute"))
	{
		if (!strcmp(perm, "read") ||
			!strcmp(perm, "write") ||
			!strcmp(perm, "execute"))
		{
			uid = geteuid();
			gid = getegid();
			
			printf("uid: %d : %s\n", uid, userNameFromId(uid));
			printf("gid: %d : %s\n", gid, groupNameFromId(gid));
			
			allowed = CheckAclPermission(path, uid, gid,
				!strcmp(perm, "read") ? ACL_READ :
				!strcmp(perm, "write") ? ACL_WRITE :
				ACL_EXECUTE);				
		}
		else
		{
			allowed = 1;
		}
		allowed |= CheckSeLinuxPermission(path, perm);
		printf("=== Access %s ===\n", allowed == ACCESS_ALLOW ? "allowed" : "denied");
		
		return 0;
	}
		
	printf("%s\n", "Error in arguments");
	
	return 0;
}
