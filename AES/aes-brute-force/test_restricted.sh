#!/bin/sh



#restricted non continuous space for key bytes: characters '0' to '9' and 'A' to 'F'

#key1:30313233_34353637_38394142_43444546
#in:  3243F6A8_885A308D_313198A2_E0370734
#out: 16EA38F0_0B3141E9_C64B24E2_1F14B69E

./aes-brute-force-fast 000000FF_00000000_FF000000_FF0000FF 30313200_34353637_00394142_00444500 3243F6A8_885A308D_313198A2_E0370734 16EA38F0_0B3141E9_C64B24E2_1F14B69E restrict 30313233_34353637_38394142_43444546


#key2:33463532_44423945_41383730_34313643
#in:  3243F6A8_885A308D_313198A2_E0370734
#out: F835CFB9_EFE228F2_1D62CB99_2B2FC59E

./aes-brute-force-fast FF0000FF_00000000_FFFFFF00_000000FF 00463500_44423945_00000030_34313600 3243F6A8_885A308D_313198A2_E0370734 F835CFB9_EFE228F2_1D62CB99_2B2FC59E restrict 30313233_34353637_38394142_43444546
./aes-brute-force-fast FF00FFFF_00000000_FFFFFF00_000000FF 00460000_44423945_00000030_34313600 3243F6A8_885A308D_313198A2_E0370734 F835CFB9_EFE228F2_1D62CB99_2B2FC59E restrict 30313233_34353637_38394142_43444546
./aes-brute-force-fast FFFFFFFF_00000000_FFFFFF00_000000FF 00000000_44423945_00000030_34313600 3243F6A8_885A308D_313198A2_E0370734 F835CFB9_EFE228F2_1D62CB99_2B2FC59E restrict 30313233_34353637_38394142_43444546


#test fully unknown key for restricted range 'A' 'C' 'G' 'T' (4 bases found in DNA)
#key3:41434754_43435447_43414141_54475447
#in:  3243F6A8_885A308D_313198A2_E0370734
#out: 14755C09_48B91E56_1642C31B_D37CA345
./aes-brute-force-fast FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF 00000000_00000000_00000000_00000000 3243F6A8_885A308D_313198A2_E0370734 14755C09_48B91E56_1642C31B_D37CA345 restrict 41434754
