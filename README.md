# Blitz Reverse Engineer Test

- You are encouraged to complete this test without use of a live-debugger and instead rely on static analysis.

Attachments:
* [blitz_test.exe](./blitz_test.exe)

I completed this task with static analysis only using IDA Pro.

### Main Function
Following the entry, I found the call to main.

```c
int main(int argc, const char **argv, const char **envp)
{
  //Variables
  
  srand(0x2384AC6u);
  printf("[ = ] Welcome to the Blitz Reverse Engineering Test!    \n");
  printf(
    "[ = ] You are encouraged to complete this test without use of a live-debugger and instead rely on a static analysis.\n\n");
  if ( argc <= 2 )
  {
    printf("[ * ] Password: ");
    scanf(std::cin, v5, &var_input);
    v6 = &v10;
    do
    {
      v6->m128i_i8[0] = rand() % 122 - 65;
      v6 = (__m128i *)((char *)v6 + 1);
    }
    while ( v6 != &var_input );
    v11.m128i_i8[15] = 0;
    v7 = 0i64;
    while ( var_input.m128i_i8[v7] == v10.m128i_i8[v7] )
    {
      if ( ++v7 >= 32 )
      {
        var_input.m128i_i64[0] = 0xDEA1EFE358611E28ui64;
        var_input.m128i_i64[1] = 0x6986AB4C02562BB8i64;
        v8 = _mm_load_si128(&var_input);
        v13.m128i_i64[0] = 0x13B7299C4EAE4B57i64;
        v10.m128i_i64[0] = 0xB1EFCFBE78403E73ui64;
        v13.m128i_i64[1] = 0x300364892A0126AAi64;
        v9 = _mm_load_si128(&v13);
        v10.m128i_i64[1] = 0xCEE8B2B633A4D98i64;
        v11.m128i_i64[1] = 0x300364892A0126AAi64;
        v11.m128i_i64[0] = 0x13B7299C448F2E25i64;
        v13 = _mm_xor_si128(v9, v11);
        var_input = _mm_xor_si128(v8, v10);
        printf(var_input.m128i_i8);
        return 1;
      }
    }
    printf("Incorrect password!\n");
    return 0;
  }
  else
  {
    sub_140001300();
    ((void (*)(void))loc_140003000)();
    return 1;
  }
}
```


The first thing I notice here is the first if statement requiring less than 3 arguments to continue to what looks like the main code which is strange. And strange usually means there is something to it. Putting that aside for now, the next thing I notice is the while loop with rand() % 122 - 65, and 122 in hex is 0x7A and 65 is 0x41. 
```c
if ( argc <= 2 )
{
    printf("[ * ] Password: ");
    scanf(std::cin, v5, &var_input);
    v6 = &v10;
    do
    {
      v6->m128i_i8[0] = rand() % 122 - 65;
      v6 = (__m128i *)((char *)v6 + 1);
    }
    while ( v6 != &var_input );
```

If you are familiar with unicode or ASCII you know that all alphabetical letters both lower and uppercase in their respective hex value fall between 0x41(A) and 0x7A(z). With that information in mind, we see that each byte in this byte array, pointed to by v6, is being set to: rand() % 122 - 65 . This means that each byte is going to be a value between -65 and 56 which means the characters being produced(no letters) are likely not going to be normal keyboard characters which could mean this is not going to be where we find our password. Going off that note, lets check out the else condition of the first if statement which we get to if we start the program with arguments.
```c
if ( argc <= 2 ){ //first part we looked at}
else
{
	sub_140001300(); 
	((void (*)(void))loc_140003000)();
	return 1;
}
```
This part already looks interesting. Lets dive right into the first function in the else condition sub_140001300.
### sub_140001300
```c
BOOL sub_140001300()
{
  //Variables

  v0 = 0;
  v1 = (char *)&loc_140003000; //encrypted function 
  do
  {
    ++v1;
    v2 = v0++ & 3;
    *(v1 - 1) ^= key1[v2];  // key1[4] = {0xC3, 0xCC, 0xE8, 0x25}
  }
  while ( v0 < 0x800 );
  return VirtualProtect(&loc_140003000, 0x800ui64, 0x20u, &flOldProtect);
}
```
So right away we see that this functions purpose is to Xor the bytes at loc_140003000 down to loc_140003000 + 0x800 with byte key[4]{0xC3, 0xCC, 0xE8, 0x25}. After the Xor decryption completes loc_140003000 is transformed into a working function, and then we return with a call to VirtualProtect and the page protection for the freshly decrypted function is changed to PAGE_EXECUTE_READ(0x20).

In order to get IDA to analyze this function that is decrypted at runtime, I copied all the bytes from loc_140003000 to loc_140003000 + 0x800 and decrypted them with the simple Xor decryption function shown below and replaced the bytes at loc_140003000 via a hex editor with the decrypted bytes. I then had IDA analyze the hex edited binary with the decrypted function in place.
```c
char key[4] = { 0xC3, 0xCC, 0xE8, 0x25 };

char payload[0x800]; 

for (int i = 0; i < sizeof(payload); i++)
{
	payload[i] ^= key[i & 3];
}
return payload;
```
After the previous function finishes the decryption, this freshly decrypted function is called:
### Decrypted Function formally known as loc_140003000
```c
void decrypted_func_140003000()
{
  //Variables

  strcpy_s(input_buffer, 0x40ui64, "J294L2Cubad{cv)4"); //[ * ]Password:
  v0 = 0;
  v1 = 0;
  v2 = &input_buffer[1];
  do
  {
    *(v2 - 1) ^= key2[v1 & 3];          // key2[4] = {0x11, 0x12, 0x13, 0x14}
    *v2 ^= key2[((_BYTE)v1 + 1) & 3];
    v2[1] ^= key2[((_BYTE)v1 - 2) & 3];
    v2[2] ^= key2[((_BYTE)v1 - 1) & 3];
    v2[3] ^= key2[v1 & 3];
    v2[4] ^= key2[((_BYTE)v1 + 1) & 3];
    v2[5] ^= key2[((_BYTE)v1 - 2) & 3];
    v2[6] ^= key2[((_BYTE)v1 - 1) & 3];
    v2[7] ^= key2[v1 & 3];
    v2[8] ^= key2[((_BYTE)v1 + 1) & 3];
    v2[9] ^= key2[((_BYTE)v1 - 2) & 3];
    v2[10] ^= key2[((_BYTE)v1 - 1) & 3];
    v2[11] ^= key2[v1 & 3];
    v2[12] ^= key2[((_BYTE)v1 + 1) & 3];
    v2[13] ^= key2[((_BYTE)v1 - 2) & 3];
    v2[14] ^= key2[((_BYTE)v1 - 1) & 3];
    v1 += 16;
    v2 += 16;
  }
  while ( v1 < 0x10 );
  printf("%s", input_buffer);
  *(_QWORD *)input_buffer = 0i64;
  v17 = 0i64;
  v18 = 15i64;
  scanf(std::cin, input_buffer);
  strcpy_s(flagPass, 0x20ui64, "s~z`kMw$eMtqtuvq"); //blitz_d0t_geegee
  flag_length = -1i64;
  do
    ++flag_length;
  while ( flagPass[flag_length] );
  count = 0;
  if ( flag_length )
  {
    countt = 0;
    p_char_flagPass = flagPass;
    do
    {										// Decrypting password/flag for comparison
      *p_char_flagPass ^= key2[countt & 3];
      ++count;
      ++p_char_flagPass;
      countt = count;
    }
    while ( count < flag_length );
  }
  v7 = input_buffer;
  v8 = *(char **)input_buffer;
  v9 = v18;
  if ( v18 >= 0x10 )
    v7 = *(char **)input_buffer;
  v10 = (char *)(flagPass - v7);
  do
  {                                             // Checking input against password
    v11 = (unsigned __int8)v10[(_QWORD)v7];
    v12 = (unsigned __int8)*v7 - v11;
    if ( v12 )
      break;
    ++v7;
  }
  while ( v11 );
  if ( v12 )
  {
    strcpy_s(input_buffer, 0x40ui64, "X|p{c`vwe2Cubad{cv2?"); //Incorrect Password!
    v14 = &input_buffer[1];
    do
    {
      *(v14 - 1) ^= key2[v0 & 3];
      *v14 ^= key2[((_BYTE)v0 + 1) & 3];
      v14[1] ^= key2[((_BYTE)v0 - 2) & 3];
      v14[2] ^= key2[((_BYTE)v0 - 1) & 3];
      v14[3] ^= key2[v0 & 3];
      v14[4] ^= key2[((_BYTE)v0 + 1) & 3];
      v14[5] ^= key2[((_BYTE)v0 - 2) & 3];
      v14[6] ^= key2[((_BYTE)v0 - 1) & 3];
      v14[7] ^= key2[v0 & 3];
      v14[8] ^= key2[((_BYTE)v0 + 1) & 3];
      v14[9] ^= key2[((_BYTE)v0 - 2) & 3];
      v14[10] ^= key2[((_BYTE)v0 - 1) & 3];
      v14[11] ^= key2[v0 & 3];
      v14[12] ^= key2[((_BYTE)v0 + 1) & 3];
      v14[13] ^= key2[((_BYTE)v0 - 2) & 3];
      v14[14] ^= key2[((_BYTE)v0 - 1) & 3];
      v14[15] ^= key2[v0 & 3];
      v14[16] ^= key2[((_BYTE)v0 + 1) & 3];
      v14[17] ^= key2[((_BYTE)v0 - 2) & 3];
      v14[18] ^= key2[((_BYTE)v0 - 1) & 3];
      v0 += 20;
      v14 += 20;
    }
    while ( v0 < 0x14 );
  }
  else
  {
    strcpy_s(input_buffer, 0x40ui64, "R}aftqg5"); //Correct!
    v13 = &input_buffer[1];
    do
    {
      *(v13 - 1) ^= key2[v0 & 3];
      *v13 ^= key2[((_BYTE)v0 + 1) & 3];
      v13[1] ^= key2[((_BYTE)v0 - 2) & 3];
      v13[2] ^= key2[((_BYTE)v0 - 1) & 3];
      v13[3] ^= key2[v0 & 3];
      v13[4] ^= key2[((_BYTE)v0 + 1) & 3];
      v13[5] ^= key2[((_BYTE)v0 - 2) & 3];
      v13[6] ^= key2[((_BYTE)v0 - 1) & 3];
      v0 += 8;
      v13 += 8;
    }
    while ( v0 < 8 );
  }
  printf("%s", input_buffer);
  if ( v9 >= 0x10 )
  {
    v15 = v8;
    if ( v9 + 1 >= 0x1000 )
    {
      v8 = (char *)*((_QWORD *)v8 - 1);
      if ( (unsigned __int64)(v15 - v8 - 8) > 0x1F )
        invalid_parameter_noinfo_noreturn();
    }
    j_j_free(v8);
  }
}
  ```
  Right off the bat we see encrypted strings being copied into a buffer to be Xor decrypted inside 'fake' while loops. The xor key being used for all strings in this function is byte key[4] { 0x11, 0x12, 0x13, 0x14}. The wierd while loops here are basically doing the same thing as this simplified version:
  ```c
char key[4] = { 0x11, 0x12, 0x13, 0x14 };

string str_decrypt = "encrypted_string_here";

for (int i = 0; i < str.length(); i++)
{
	str_decrypt[i] ^= key[i & 3];
}
return str_decrypt;
```
The first string "J294L2Cubad{cv)4" decrypts to "[ * ] Password:" which is then used to prompt the user to enter their input. The next string "s~z`kMw$eMtqtuvq" is decrypted to "blitz_d0t_geegee", which is the password/flag we have been looking for because it is the only string compared against user input to determine which string is decrypted and printed next.  If the user input and password match then the string "R}aftqg5" is decrypted to "Correct!" and printed to the console. Thanks to Blitz for supplying me with their test program to reverse!
## Flag
> blitz_d0t_geegee

