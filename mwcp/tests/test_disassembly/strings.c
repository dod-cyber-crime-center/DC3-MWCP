#include <stdio.h>
#include <string.h>

char string01[] = "Idmmn!Vnsme ";
char string02[] = "Vgqv\"qvpkle\"ukvj\"ig{\"2z20";
char string03[] = "Wkf#rvj`h#aqltm#el{#ivnsp#lufq#wkf#obyz#gld-";
char string04[] = "Keo$mw$wpvkjc$ej`$ehwk$cmraw$wle`a*";
char string05[] = "Dfla%gpwkv%mji`v%lk%rjji%fijqm+";
char string06[] = "Egru&ghb&biau&cgen&ngrc&rnc&irnct(";
char string13[] = "\\cv}3g{v3pargv3qfg3w|}4g3qavrx3g{v3t\x7fr``=";
char string17[] = "C\x7frer7c\x7fr7q{xxs7zve|7~d7cry7~yt\x7frd9";
char string1a[] = "+()./,-\"#*";
char string23[] = "`QFBWFsQL@FPPb";
char string27[] = "tSUdFS";
char string40[] = "\x01\x13\x10n\x0e\x05\x14";
char string46[] = "-\",5 , v,tr4v,trv4t,v\x7f,ttt";
char string73[] = "@AKJDGBA@KJGDBJKAGDC";
char string75[] = "!\x1d\x10U\x05\x14\x06\x01U\x02\x1c\x19\x19U\x19\x1a\x1a\x1eU\x17\x07\x1c\x12\x1d\x01\x10\x07U\x01\x1a\x18\x1a\x07\x07\x1a\x02[";
char string77[] = "4\x16\x05\x04W\x16\x19\x13W\x15\x02\x04\x04\x12\x04W\x04\x03\x16\x1b\x1b\x12\x13W\x1e\x19W\x04\x16\x19\x13W\x13\x05\x1e\x11\x03\x04Y";
char string7a[] = ".\x12\x1fZ\x10\x1b\x19\x11\x1f\x0eZ\x12\x0f\x14\x1dZ\x15\x14Z\x0e\x12\x1fZ\x18\x1b\x19\x11Z\x15\x1cZ\x0e\x12\x1fZ\r\x13\x1e\x1fZ\x19\x12\x1b\x13\x08T";
char string7f[] = "LMFOGHKNLMGFOHKFGNLKHNMLOKGNKGHFGLHKGLMHKGOFNMLHKGFNLMJNMLIJFGNMLOJIMLNGFJHNM";;



void encrypt(char *s, char key)
{
	while (*s)
		*s++ ^= key;
}

void decrypt()
{
	encrypt(&string01[0], 0x01);
	encrypt(&string02[0], 0x02);
	encrypt(&string03[0], 0x03);
	encrypt(&string04[0], 0x04);
	encrypt(&string05[0], 0x05);
	encrypt(&string06[0], 0x06);
	encrypt(&string13[0], 0x13);
	encrypt(&string17[0], 0x17);
	encrypt(&string1a[0], 0x1a);
	encrypt(&string23[0], 0x23);
	encrypt(&string27[0], 0x27);
	encrypt(&string40[0], 0x40);
	encrypt(&string46[0], 0x46);
	encrypt(&string73[0], 0x73);
	encrypt(&string75[0], 0x75);
	encrypt(&string77[0], 0x77);
	encrypt(&string7a[0], 0x7a);
	encrypt(&string7f[0], 0x7f);
}

int main()
{
	decrypt();
	printf("%s\n", string01);
	printf("%s\n", string02);
	printf("%s\n", string03);
	printf("%s\n", string04);
	printf("%s\n", string05);
	printf("%s\n", string06);
	printf("%s\n", string13);
	printf("%s\n", string17);
	printf("%s\n", string1a);
	printf("%s\n", string23);
	printf("%s\n", string27);
	printf("%s\n", string40);
	printf("%s\n", string46);
	printf("%s\n", string73);
	printf("%s\n", string75);
	printf("%s\n", string77);
	printf("%s\n", string7a);
	printf("%s\n", string7f);

    return 0;
}
