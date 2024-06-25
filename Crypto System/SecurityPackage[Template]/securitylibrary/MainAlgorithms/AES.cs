using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
	/// <summary>
	/// If the string starts with 0x.... then it's Hexadecimal not string
	/// </summary>
	public class AES : CryptographicTechnique
	{

		public static string[,] sbox = new string[16, 16] {
                // 0     1     2     3     4     5     6     7     8     9     A    B      C     D     E      F
                {"63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76"},// 0 t
                {"CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0"},// 1 t
                {"B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15"},// 2 t
                {"04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75"},// 3 t
                {"09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84"},// 4 t
                {"53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF"},// 5 t
                {"D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8"},// 6 t
                {"51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2"},// 7 t
                {"CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73"},// 8 t
                {"60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB"},// 9 t
                {"E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79"},// A t
                {"E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08"},// B t
                {"BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A"},// C t
                {"70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E"},// D t
                {"E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF"},// E t
                {"8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16"},// F t
            };

		public static string[,] inverseSBox = new string[16, 16]
			{
	{"52", "09", "6A", "D5", "30", "36", "A5", "38", "BF", "40", "A3", "9E", "81", "F3", "D7", "FB"},
	{"7C", "E3", "39", "82", "9B", "2F", "FF", "87", "34", "8E", "43", "44", "C4", "DE", "E9", "CB"},
	{"54", "7B", "94", "32", "A6", "C2", "23", "3D", "EE", "4C", "95", "0B", "42", "FA", "C3", "4E"},
	{"08", "2E", "A1", "66", "28", "D9", "24", "B2", "76", "5B", "A2", "49", "6D", "8B", "D1", "25"},
	{"72", "F8", "F6", "64", "86", "68", "98", "16", "D4", "A4", "5C", "CC", "5D", "65", "B6", "92"},
	{"6C", "70", "48", "50", "FD", "ED", "B9", "DA", "5E", "15", "46", "57", "A7", "8D", "9D", "84"},
	{"90", "D8", "AB", "00", "8C", "BC", "D3", "0A", "F7", "E4", "58", "05", "B8", "B3", "45", "06"},
	{"D0", "2C", "1E", "8F", "CA", "3F", "0F", "02", "C1", "AF", "BD", "03", "01", "13", "8A", "6B"},
	{"3A", "91", "11", "41", "4F", "67", "DC", "EA", "97", "F2", "CF", "CE", "F0", "B4", "E6", "73"},
	{"96", "AC", "74", "22", "E7", "AD", "35", "85", "E2", "F9", "37", "E8", "1C", "75", "DF", "6E"},
	{"47", "F1", "1A", "71", "1D", "29", "C5", "89", "6F", "B7", "62", "0E", "AA", "18", "BE", "1B"},
	{"FC", "56", "3E", "4B", "C6", "D2", "79", "20", "9A", "DB", "C0", "FE", "78", "CD", "5A", "F4"},
	{"1F", "DD", "A8", "33", "88", "07", "C7", "31", "B1", "12", "10", "59", "27", "80", "EC", "5F"},
	{"60", "51", "7F", "A9", "19", "B5", "4A", "0D", "2D", "E5", "7A", "9F", "93", "C9", "9C", "EF"},
	{"A0", "E0", "3B", "4D", "AE", "2A", "F5", "B0", "C8", "EB", "BB", "3C", "83", "53", "99", "61"},
	{"17", "2B", "04", "7E", "BA", "77", "D6", "26", "E1", "69", "14", "63", "55", "21", "0C", "7D"}
};

		public static string[,] createMatrix(string state, int rows, int columns)
		{
			string[,] matrix = new string[rows, columns];

			// skip 0x
			int counter = 2;

			for (int i = 0; i < columns; i++)
			{
				for (int j = 0; j < rows; j++)
				{

					char ch1 = state[counter];
					char ch2 = state[counter + 1];

					if ((int)ch1 > 95)
					{
						ch1 = (char)((int)ch1 - 32);
					}
					if ((int)ch2 > 95)
					{
						ch2 = (char)((int)ch2 - 32);
					}

					string c1 = ch1.ToString();
					string c2 = ch2.ToString();


					string cell = c1 + c2;

					matrix[j, i] = cell;
					counter += 2;
				}
			}

			return matrix;
		}

		public static string createState(string[,] matrix, int rows, int columns)
		{
			string state = "0x";
			for (int i = 0; i < columns; i++)
			{
				for (int j = 0; j < rows; j++)
				{

					state += matrix[j, i];
				}
			}
			return state;
		}

		public static void printMatrix(string[,] t, int rows, int columns)
		{
			for (int i = 0; i < rows; i++)
			{
				for (int j = 0; j < columns; j++)
				{

					Console.Write(t[i, j] + " ");
				}
				Console.WriteLine();
			}

		}

		public static string hexTobin(string hex)
		{
			string bin = Convert.ToString(Convert.ToInt32(hex, 16), 2).PadLeft(8, '0');
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
			//Console.WriteLine(resXOR);
			string resHex = binTohex(resXOR);

			return resHex;
		}

		public static string[,] SubBytes(string[,] input, string[,] SB)
		{
			string[,] output = new string[4, 4];
			for (int i = 0; i < 4; i++)
			{
				for (int j = 0; j < 4; j++)
				{
					string cell = input[i, j];
					string c1 = cell[0].ToString();
					string c2 = "";

					if (cell.Length == 1)
					{
						c1 = "0";
						c2 = cell[0].ToString();
					}
					else
					{
						c2 = cell[1].ToString();
					}

					int x = 0;
					int y = 0;

					if (c1 == "A")
					{
						x = 10;
					}
					else if (c1 == "B")
					{
						x = 11;
					}
					else if (c1 == "C")
					{
						x = 12;
					}
					else if (c1 == "D")
					{
						x = 13;
					}
					else if (c1 == "E")
					{
						x = 14;
					}
					else if (c1 == "F")
					{
						x = 15;
					}
					else
					{
						x = int.Parse(c1);
					}

					if (c2 == "A")
					{
						y = 10;
					}
					else if (c2 == "B")
					{
						y = 11;
					}
					else if (c2 == "C")
					{
						y = 12;
					}
					else if (c2 == "D")
					{
						y = 13;
					}
					else if (c2 == "E")
					{
						y = 14;
					}
					else if (c2 == "F")
					{
						y = 15;
					}
					else
					{
						y = int.Parse(c2);
					}


					output[i, j] = SB[x, y];


				}
			}


			return output;
		}

		public static string[] ShiftRows(string[] input, int rows)
		{

			while (rows != 0)
			{
				string[] copyarray = new string[4];
				for (int i = 0; i < 4; i++)
					copyarray[i] = input[i];

				string temp = input[0];
				for (int i = 0; i < 3; i++)
					input[i] = copyarray[i + 1];
				input[3] = temp;
				rows--;
			}

			return input;
		}

		public static string mixColumns(string hex1, string hex2)
		{

			string res = "";

			string c2 = hex2[1].ToString();

			string bin1 = hexTobin(hex1);
			string c1 = bin1[0].ToString();


			if (c2 == "1")
			{
				res = hex1;
			}
			else if (c2 == "2")
			{
				if (c1 == "0")
				{
					string copyarray = "";
					for (int i = 0; i < 7; i++)
						copyarray += bin1[i + 1].ToString();

					copyarray += "0";
					res = binTohex(copyarray);
				}
				else if (c1 == "1")
				{
					string copyarray = "";
					for (int i = 0; i < 7; i++)
						copyarray += bin1[i + 1].ToString();

					copyarray += "0";
					string hex = binTohex(copyarray);
					res = XOR(hex, "1B");
				}
			}
			else if (c2 == "3")
			{
				string res1 = "";
				string res2 = hex1;
				if (c1 == "0")
				{
					string copyarray = "";
					for (int i = 0; i < 7; i++)
						copyarray += bin1[i + 1].ToString();

					copyarray += "0";
					res1 = binTohex(copyarray);
				}
				else if (c1 == "1")
				{
					string copyarray = "";
					for (int i = 0; i < 7; i++)
						copyarray += bin1[i + 1].ToString();

					copyarray += "0";
					string hex = binTohex(copyarray);
					res1 = XOR(hex, "1B");
				}

				res = XOR(res1, res2);
			}

			return res;
		}

		public static string add(string[] sum)
		{
			string res1 = sum[0];
			string res2 = XOR(res1, sum[1]);
			string res3 = XOR(sum[2], sum[3]);
			string res = XOR(res3, res2);

			return res;
		}

		public static string[] createFirstColumn(string[,] rcon, string[,] lastKey, int round)
		{
			string[] column = new string[4];

			string[] lastColumn = new string[4];
			string[] copyarray = new string[4];

			for (int c = 0; c < 4; c++)
				copyarray[c] = lastKey[c, 3];

			string[] firstColumn = new string[4];
			for (int c = 0; c < 4; c++)
				firstColumn[c] = lastKey[c, 0];

			string[] selectedRcon = new string[4];
			for (int c = 0; c < 4; c++)
				selectedRcon[c] = rcon[c, round];

			// rotate first element

			string temp = copyarray[0];
			for (int c = 0; c < 3; c++)
				lastColumn[c] = copyarray[c + 1];

			lastColumn[3] = temp;

			for (int i = 0; i < 4; i++)
			{
				string cell = lastColumn[i];
				string c1 = cell[0].ToString();
				string c2 = "";
				if (cell.Length == 1)
				{
					c1 = "0";
					c2 = cell[0].ToString();
				}
				else
				{
					c2 = cell[1].ToString();
				}
				if (c1 == "A")
				{
					c1 = "10";
				}
				else if (c1 == "B")
				{
					c1 = "11";
				}
				else if (c1 == "C")
				{
					c1 = "12";
				}
				else if (c1 == "D")
				{
					c1 = "13";
				}
				else if (c1 == "E")
				{
					c1 = "14";
				}
				else if (c1 == "F")
				{
					c1 = "15";
				}
				if (c2 == "A")
				{
					c2 = "10";
				}
				else if (c2 == "B")
				{
					c2 = "11";
				}
				else if (c2 == "C")
				{
					c2 = "12";
				}
				else if (c2 == "D")
				{
					c2 = "13";
				}
				else if (c2 == "E")
				{
					c2 = "14";
				}
				else if (c2 == "F")
				{
					c2 = "15";
				}

				int x = int.Parse(c1);
				int y = int.Parse(c2);

				lastColumn[i] = sbox[x, y];
			}


			for (int i = 0; i < 4; i++)
				column[i] = XOR(firstColumn[i], XOR(lastColumn[i], selectedRcon[i]));

			return column;
		}

		public static string[,] createRoundKey(string[,] lastKey, string[] firstColumn)
		{
			string[,] roundKey = new string[4, 4];

			for (int i = 0; i < 4; i++)
			{
				for (int j = 0; j < 1; j++)
				{
					roundKey[i, j] = firstColumn[i];
				}
			}

			for (int i = 0; i < 4; i++)
			{
				for (int j = 1; j < 4; j++)
				{
					roundKey[i, j] = XOR(roundKey[i, j - 1], lastKey[i, j]);
				}
			}


			return roundKey;

		}

		public static string[,] createRoundKeys(string[,] cipherkey)
		{
			int round = 10;
			string[,] keyMatrixRounds = new string[4, 40];

			string[,] key = new string[4, 4];

			key = cipherkey;

			string[,] rcon = new string[4, 10] {
				{"01", "02", "04", "08", "10", "20", "40", "80", "1B", "36"},
				{"00", "00", "00", "00", "00", "00", "00", "00", "00", "00"},
				{"00", "00", "00", "00", "00", "00", "00", "00", "00", "00"},
				{"00", "00", "00", "00", "00", "00", "00", "00", "00", "00"}
			};


			for (int r = 0; r < round; r++)
			{

				string[] firstColumn = new string[4];
				firstColumn = createFirstColumn(rcon, key, r);

				string[,] lastroundKey = new string[4, 4];
				lastroundKey = key;

				string[,] nextroundKey = new string[4, 4];

				nextroundKey = createRoundKey(lastroundKey, firstColumn);

				for (int j = (r * 4), c = 0; j < (r * 4) + 4; j++, c++)
				{
					for (int i = 0; i < 4; i++)
					{
						keyMatrixRounds[i, j] = nextroundKey[i, c];
					}
				}

				key = nextroundKey;

			}


			return keyMatrixRounds;
		}

		public static string[,] addRoundKey(string[,] outputMixColumns, string[,] roundKey)
		{
			string[,] output = new string[4, 4];

			for (int i = 0; i < 4; i++)
			{
				for (int j = 0; j < 4; j++)
				{
					output[i, j] = XOR(outputMixColumns[i, j], roundKey[i, j]);
				}
			}

			return output;

		}

		public static string[,] aes(string[,] plainMatrix, string[,] cipherKey)
		{
			string[,] cipherMatrix = new string[4, 4];

			for (int round = 0; round < 9; round++)
			{
				// SubBytes

				string[,] sbox = new string[16, 16] {
                // 0     1     2     3     4     5     6     7     8     9     A    B      C     D     E      F
                {"63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76"},// 0
                {"CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0"},// 1
                {"B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15"},// 2
                {"04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75"},// 3
                {"09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84"},// 4
                {"53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF"},// 5
                {"D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8"},// 6
                {"51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2"},// 7
                {"CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73"},// 8
                {"60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB"},// 9
                {"E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79"},// A
                {"E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08"},// B
                {"BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A"},// C
                {"70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E"},// D
                {"E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF"},// E
                {"8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16"},// F
            };

				string[,] outputSubBytes = new string[4, 4];
				outputSubBytes = SubBytes(plainMatrix, sbox);


				// shiftRows


				string[,] outputShiftRows = new string[4, 4];

				for (int i = 0; i < 4; i++)
					outputShiftRows[0, i] = outputSubBytes[0, i];

				for (int i = 1; i < 4; i++)
				{
					string[] shiftrow = new string[4];
					string[] copyarray = new string[4];
					for (int c = 0; c < 4; c++)
						copyarray[c] = outputSubBytes[i, c];

					shiftrow = ShiftRows(copyarray, i);
					for (int j = 0; j < 4; j++)
					{
						outputShiftRows[i, j] = shiftrow[j];
					}
				}

				// mixColumns

				string[,] galiosFieldMatrix = new string[4, 4] {
				{"02", "03", "01", "01" },
				{"01", "02", "03", "01" },
				{"01", "01", "02", "03" },
				{"03", "01", "01", "02" }
			};

				string[,] outputMixColumns = new string[4, 4];

				for (int i = 0; i < 4; i++)
				{
					for (int j = 0; j < 4; j++)
					{
						string[] sum = new string[4];
						for (int z = 0; z < 4; z++)
						{

							sum[z] = mixColumns((outputShiftRows[z, i]), (galiosFieldMatrix[j, z]));

						}
						outputMixColumns[j, i] = add(sum);

					}

				}


				// addRoundKey
				string[,] rcon = new string[4, 10] {
				{"01", "02", "04", "08", "10", "20", "40", "80", "1B", "36"},
				{"00", "00", "00", "00", "00", "00", "00", "00", "00", "00"},
				{"00", "00", "00", "00", "00", "00", "00", "00", "00", "00"},
				{"00", "00", "00", "00", "00", "00", "00", "00", "00", "00"}
			};

				string[,] roundKey = new string[4, 4];

				string[] firstColumn = new string[4];


				firstColumn = createFirstColumn(rcon, cipherKey, round);
				roundKey = createRoundKey(cipherKey, firstColumn);


				string[,] outputAddRoundKey = new string[4, 4];
				outputAddRoundKey = addRoundKey(outputMixColumns, roundKey);

				// next round

				for (int i = 0; i < 4; i++)
				{
					for (int j = 0; j < 4; j++)
					{
						plainMatrix[i, j] = outputAddRoundKey[i, j];
						cipherKey[i, j] = roundKey[i, j];
					}
				}

			}


			// last round

			// subBytes

			string[,] sbox2 = new string[16, 16] {
                // 0     1     2     3     4     5     6     7     8     9     A    B      C     D     E      F
                {"63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76"},// 0
                {"CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0"},// 1
                {"B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15"},// 2
                {"04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75"},// 3
                {"09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84"},// 4
                {"53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF"},// 5
                {"D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8"},// 6
                {"51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2"},// 7
                {"CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73"},// 8
                {"60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB"},// 9
                {"E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79"},// A
                {"E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08"},// B
                {"BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A"},// C
                {"70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E"},// D
                {"E1", "F8", "98", "11", "69", "D9", "BE", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF"},// E
                {"8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16"},// F
            };
			string[,] outputSubBytes2 = new string[4, 4];
			outputSubBytes2 = SubBytes(plainMatrix, sbox);

			// shift rows

			string[,] outputShiftRows2 = new string[4, 4];

			for (int i = 0; i < 4; i++)
				outputShiftRows2[0, i] = outputSubBytes2[0, i];

			for (int i = 1; i < 4; i++)
			{
				string[] shiftrow = new string[4];
				string[] copyarray = new string[4];
				for (int c = 0; c < 4; c++)
					copyarray[c] = outputSubBytes2[i, c];

				shiftrow = ShiftRows(copyarray, i);
				for (int j = 0; j < 4; j++)
				{
					outputShiftRows2[i, j] = shiftrow[j];
				}
			}



			string[,] rcon2 = new string[4, 10] {
				{"01", "02", "04", "08", "10", "20", "40", "80", "1B", "36"},
				{"00", "00", "00", "00", "00", "00", "00", "00", "00", "00"},
				{"00", "00", "00", "00", "00", "00", "00", "00", "00", "00"},
				{"00", "00", "00", "00", "00", "00", "00", "00", "00", "00"}
			};

			string[,] roundKey2 = new string[4, 4];

			string[] firstColumn2 = new string[4];


			firstColumn2 = createFirstColumn(rcon2, cipherKey, 9);
			roundKey2 = createRoundKey(cipherKey, firstColumn2);


			string[,] outputAddRoundKey2 = new string[4, 4];
			cipherMatrix = addRoundKey(outputShiftRows2, roundKey2);


			return cipherMatrix;

		}

		public static string[] shift(string bin)
		{
			string[] shiftResult = new string[4];

			shiftResult[0] = bin;

			string copyBin = shiftResult[0];

			for (int i = 1; i < 4; i++)
			{

				for (int j = 0; j < 7; j++)
				{
					shiftResult[i] += copyBin[j + 1];
				}

				shiftResult[i] += '0';

				string check = copyBin[0].ToString();

				if (check == "1")
				{

					string hex = binTohex(shiftResult[i]);
					shiftResult[i] = hexTobin(XOR(hex, "1B"));
				}

				copyBin = shiftResult[i];

			}


			return shiftResult;
		}

		public static string[] ShiftRowsRight(string[] input, int rows)
		{

			while (rows != 0)
			{
				string[] copyarray = new string[4];
				for (int i = 0; i < 4; i++)
					copyarray[i] = input[i];

				string temp = input[3];
				for (int i = 0; i < 3; i++)
					input[i + 1] = copyarray[i];
				input[0] = temp;
				rows--;
			}

			return input;
		}


		public static string InvMixColumns(string bin, string[] shifts)
		{
			string bin1 = "";

			for (int i = 4; i < 8; i++)
				bin1 += bin[i];

			string mixColumns = "";

			string selectedShifts = "";

			for (int i = 3; i >= 0; i--)
			{
				if (bin1[i].ToString() == "1")
				{
					selectedShifts += shifts[3 - i];
				}
			}

			string first = selectedShifts.Substring(0, 8);
			string second = selectedShifts.Substring(8, 8);

			string third = "";

			if (selectedShifts.Length > 16)
			{
				third = selectedShifts.Substring(16, 8);
			}

			string num1 = binTohex(first);
			string num2 = binTohex(second);

			if (selectedShifts.Length == 16)
			{
				mixColumns = XOR(num1, num2);
			}
			else
			{
				string num3 = binTohex(third);

				mixColumns = XOR(XOR(num1, num2), num3);
			}

			return mixColumns;
		}

		public static string[,] decryption(string[,] cipherMatrix, string[,] keyMatrixRounds, string[,] key)
		{
			string[,] plainMatrix = new string[4, 4];


			for (int round = 1; round < 10; round++)
			{
				// add round key
				string[,] lastkey = new string[4, 4];

				for (int i = 0; i < 4; i++)
				{
					for (int j = (9 - round) * 4, c = 0; j < ((9 - round) * 4) + 4; j++, c++)
					{
						lastkey[i, c] = keyMatrixRounds[i, j];
					}
				}

				string[,] outputAddRoundKey = new string[4, 4];

				outputAddRoundKey = addRoundKey(cipherMatrix, lastkey);

				// mix columns


				string[,] InvGaliosFieldMatrix = new string[4, 4] {
				{"E", "B", "D", "9" },
				{"9", "E", "B", "D" },
				{"D", "9", "E", "B" },
				{"B", "D", "9", "E" }
			};

				string[,] outputMixColumns = new string[4, 4];

				for (int i = 0; i < 4; i++)
				{
					for (int j = 0; j < 4; j++)
					{
						string[] sum = new string[4];
						for (int z = 0; z < 4; z++)
						{

							sum[z] = InvMixColumns(hexTobin(InvGaliosFieldMatrix[j, z]), shift(hexTobin(outputAddRoundKey[z, i])));

						}
						outputMixColumns[j, i] = add(sum);

					}

				}

				// shift rows right

				string[,] outputShiftRows = new string[4, 4];

				for (int i = 0; i < 4; i++)
					outputShiftRows[0, i] = outputMixColumns[0, i];

				for (int i = 1; i < 4; i++)
				{
					string[] shiftrow = new string[4];
					string[] copyarray = new string[4];
					for (int c = 0; c < 4; c++)
						copyarray[c] = outputMixColumns[i, c];

					shiftrow = ShiftRowsRight(copyarray, i);
					for (int j = 0; j < 4; j++)
					{
						outputShiftRows[i, j] = shiftrow[j];
					}
				}


				// SubBytes

				string[,] outputSubBytes = new string[4, 4];
				outputSubBytes = SubBytes(outputShiftRows, inverseSBox);


				// next round

				for (int i = 0; i < 4; i++)
				{
					for (int j = 0; j < 4; j++)
					{
						cipherMatrix[i, j] = outputSubBytes[i, j];
					}
				}

			}

			plainMatrix = addRoundKey(cipherMatrix, key);

			return plainMatrix;

		}



		public override string Decrypt(string cipherText, string key)
		{
			string[,] cipherMatrix = new string[4, 4];
			cipherMatrix = createMatrix(cipherText, 4, 4);

			string[,] keyMatrix = new string[4, 4];
			keyMatrix = createMatrix(key, 4, 4);


			// create round keys
			string[,] keyMatrixRounds = new string[4, 40];

			keyMatrixRounds = createRoundKeys(keyMatrix);

			// last round

			// add round key
			string[,] lastkey = new string[4, 4];
			int round = 0;

			for (int i = 0; i < 4; i++)
			{
				for (int j = (9 - round) * 4, c = 0; j < ((9 - round) * 4) + 4; j++, c++)
				{
					lastkey[i, c] = keyMatrixRounds[i, j];
				}
			}

			string[,] outputAddRoundKey = new string[4, 4];

			outputAddRoundKey = addRoundKey(cipherMatrix, lastkey);

			// shift rows right

			string[,] outputShiftRows = new string[4, 4];

			for (int i = 0; i < 4; i++)
				outputShiftRows[0, i] = outputAddRoundKey[0, i];

			for (int i = 1; i < 4; i++)
			{
				string[] shiftrow = new string[4];
				string[] copyarray = new string[4];
				for (int c = 0; c < 4; c++)
					copyarray[c] = outputAddRoundKey[i, c];

				shiftrow = ShiftRowsRight(copyarray, i);
				for (int j = 0; j < 4; j++)
				{
					outputShiftRows[i, j] = shiftrow[j];
				}
			}


			// SubBytes

			string[,] outputSubBytes = new string[4, 4];
			outputSubBytes = SubBytes(outputShiftRows, inverseSBox);

			string[,] plain = new string[4, 4];

			plain = decryption(outputSubBytes, keyMatrixRounds, keyMatrix);

			//printMatrix(plain, 4, 4);

			string plainText = "0x";

			for (int i = 0; i < 4; i++)
			{
				for (int j = 0; j < 4; j++)
				{
					if (plain[j, i].Length == 1)
					{
						plainText += "0";
					}
					plainText += plain[j, i];
				}
			}

			return plainText;

		}
		public override string Encrypt(string plainText, string key)
		{
			string[,] plainMatrix = new string[4, 4];
			plainMatrix = createMatrix(plainText, 4, 4);

			string[,] keyMatrix = new string[4, 4];
			keyMatrix = createMatrix(key, 4, 4);



			// intial round xor plaintext with key

			string[,] plainMatrix2 = new string[4, 4];

			plainMatrix2 = addRoundKey(plainMatrix, keyMatrix);

			string[,] cipherMatrix = new string[4, 4];

			cipherMatrix = aes(plainMatrix2, keyMatrix);

			string cipherText = "0x";

			for (int i = 0; i < 4; i++)
			{
				for (int j = 0; j < 4; j++)
				{
					if (cipherMatrix[j, i].Length == 1)
					{
						cipherText += "0";
					}
					cipherText += cipherMatrix[j, i];
				}
			}

			return cipherText;
		}
	}
}
