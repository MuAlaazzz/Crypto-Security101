using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
	/// <summary>
	/// If the string starts with 0x.... then it's Hexadecimal not string
	/// </summary>
	public class DES : CryptographicTechnique
	{
		public static int[][,] sbox = {

				new int[,] {
					{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
					{0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
					{4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
					{15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
				},

				new int[,] {
					{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
					{3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
					{0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
					{13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9},
				},

				new int[,] {
					{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
					{13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
					{13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
					{1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
				},

				new int[,]
				{
					{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
					{13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
					{10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
					{3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
				},

				new int[,]
				{
					{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
					{14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
					{4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
					{11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
				},

				new int[,]
				{
					{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
					{10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
					{9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
					{4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
				},

				new int[,]
				{
					{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
					{13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
					{1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
					{6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
				},

				new int[,]
				{
					{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
					{1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
					{7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
					{2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
				}

			};

		// for key

		public static int[] PC1 = new int[56] { 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 56, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4 };
		public static int[] PC2 = new int[48] { 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32 };

		// for plain

		public static int[] IP = new int[64] { 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7 };

		public static string hexTobin(string hex)
		{
			string bin = Convert.ToString(Convert.ToInt32(hex, 16), 2).PadLeft(4, '0');
			return bin;
		}

		public static string binTohex(string bin)
		{
			int decimalNum = Convert.ToInt32(bin, 2);
			string hex = decimalNum.ToString("X");
			return hex;
		}

		public static string XOR(string hex1, string hex2)
		{
			string bin1 = hexTobin(hex1);
			string bin2 = hexTobin(hex2);

			string resXOR = "";

			for (int i = 0; i < bin1.Length; i++)
			{
				if (bin1[i] == bin2[i])
				{
					resXOR += '0';
				}
				else
				{
					resXOR += '1';
				}
			}
			string resHex = binTohex(resXOR);

			return resHex;
		}

		public static string stringToBinary(string state, int size)
		{
			string res = "";

			// skip 0x

			for (int i = 2; i < size; i++)
			{
				char ch = state[i];
				string bin = hexTobin(ch.ToString());

				res += bin;

			}

			return res;
		}

		public static string shiftLeft(string state, int numOfShifts)
		{
			string res = "";
			string copy = state;
			for (int j = 0; j < numOfShifts; j++)
			{
				string res2 = "";
				char ch = copy[0];

				for (int i = 0; i < state.Length - 1; i++)
				{
					res2 += copy[i + 1].ToString();
				}

				res2 += ch.ToString();

				copy = res2;
			}

			res = copy;

			return res;
		}

		public static string[] createLeftRightKey(string state, int[] numOfShifts)
		{
			string[] res = new string[16];

			for (int i = 0; i < 16; i++)
			{
				res[i] = shiftLeft(state, numOfShifts[i]);
				state = res[i];
			}

			return res;
		}

		public static string[] createKey16(string[] left, string[] right, int[] PC2)
		{
			string[] res = new string[16];

			for (int i = 0; i < 16; i++)
			{
				string state = left[i] + right[i];
				string res2 = "";
				for (int j = 0; j < PC2.Length; j++)
				{
					res2 += state[PC2[j] - 1].ToString();
				}

				res[i] = res2;

			}


			return res;
		}

		public static string des(string plain, string[] key)
		{
			string cipher = "0x";

			int[] EBit = new int[48]
			{
				32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1
			};

			int[] PTable = new int[32]
			{
				16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25
			};

			int[] IPnot1 = new int[64]
			{
				40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25
			};

			string plainLeft2 = "";
			string plainLeft = plain.Substring(0, 32);
			string plainRight = plain.Substring(32, 32);


			for (int counter = 0; counter < 16; counter++)
			{
				string k = key[counter];
				plainLeft2 = plainRight;

				// E-Bit Table

				string E_Right = "";

				for (int i = 0; i < EBit.Length; i++)
				{
					char ch = plainRight[EBit[i] - 1];
					E_Right += ch.ToString();
				}

				// XOR k[n] + E(R[n-1])

				string resXOR1 = "";

				for (int i = 0; i < E_Right.Length; i++)
				{
					if (E_Right[i] == k[i])
					{
						resXOR1 += '0';
					}
					else
					{
						resXOR1 += '1';
					}
				}

				// sbox

				string resSbox = "";

				for (int j = 0; j < 8; j++)
				{
					string block = resXOR1.Substring(j * 6, 6);

					string row = binTohex(block[0].ToString() + block[5].ToString());
					string col = binTohex(block.Substring(1, 4));

					resSbox += hexTobin((sbox[j][Convert.ToInt32(row, 16), Convert.ToInt32(col, 16)]).ToString("X"));

				}

				// P table

				string resPTable = "";

				for (int i = 0; i < PTable.Length; i++)
				{
					char ch = resSbox[PTable[i] - 1];
					resPTable += ch.ToString();
				}

				// R[n] = XOR L[n-1] + F(R[n-1],K[n])

				string resXOR2 = "";

				for (int i = 0; i < resPTable.Length; i++)
				{
					if (resPTable[i] == plainLeft[i])
					{
						resXOR2 += '0';
					}
					else
					{
						resXOR2 += '1';
					}
				}

				plainRight = resXOR2;
				plainLeft = plainLeft2;
			}

			string res = plainRight + plainLeft;

			// ip^-1 table

			string resIP = "";

			for (int i = 0; i < IPnot1.Length; i++)
			{
				char ch = res[IPnot1[i] - 1];
				resIP += ch.ToString();

			}

			for (int i = 0; i < (resIP.Length) / 4; i++)
			{
				string block = resIP.Substring(4 * i, 4);
				cipher += binTohex(block);
			}

			return cipher;
		}

		public override string Decrypt(string cipherText, string key)
		{
			string keyBinary64 = stringToBinary(key, key.Length);

			string keyBinary56 = "";

			for (int i = 0; i < PC1.Length; i++)
			{
				char ch = keyBinary64[PC1[i] - 1];
				keyBinary56 += ch.ToString();
			}


			string[] key16 = new string[16];

			string[] keyLeft = new string[16];
			string[] keyRight = new string[16];

			int[] nummberOfShift = new int[16] { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

			// substring(start index,Length) 

			string keyLeft0 = keyBinary56.Substring(0, 28);
			string keyRight0 = keyBinary56.Substring(28, 28);

			keyLeft = createLeftRightKey(keyLeft0, nummberOfShift);
			keyRight = createLeftRightKey(keyRight0, nummberOfShift);

			key16 = createKey16(keyLeft, keyRight, PC2);


			string[] inverseKey16 = new string[16];

			for (int i = 0; i < 16; i++)
			{
				inverseKey16[i] = key16[15 - i];
			}

			string cipherBinary = stringToBinary(cipherText, cipherText.Length);

			string cipherBinary2 = "";

			for (int i = 0; i < IP.Length; i++)
			{
				char ch = cipherBinary[IP[i] - 1];
				cipherBinary2 += ch.ToString();
			}


			string plain = des(cipherBinary2, inverseKey16);

			return plain;

		}

		public override string Encrypt(string plainText, string key)
		{
			string plainBinary = stringToBinary(plainText, plainText.Length);
			string keyBinary64 = stringToBinary(key, key.Length);

			string keyBinary56 = "";

			for (int i = 0; i < PC1.Length; i++)
			{
				char ch = keyBinary64[PC1[i] - 1];
				keyBinary56 += ch.ToString();
			}


			string[] key16 = new string[16];

			string[] keyLeft = new string[16];
			string[] keyRight = new string[16];

			int[] nummberOfShift = new int[16] { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

			// substring(start index,Length) 

			string keyLeft0 = keyBinary56.Substring(0, 28);
			string keyRight0 = keyBinary56.Substring(28, 28);

			keyLeft = createLeftRightKey(keyLeft0, nummberOfShift);
			keyRight = createLeftRightKey(keyRight0, nummberOfShift);

			key16 = createKey16(keyLeft, keyRight, PC2);



			string plainBinary2 = "";

			for (int i = 0; i < IP.Length; i++)
			{
				char ch = plainBinary[IP[i] - 1];
				plainBinary2 += ch.ToString();
			}


			string cipher = des(plainBinary2, key16);

			return cipher;

		}
	}
}
