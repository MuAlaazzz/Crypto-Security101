using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
	public class PlayFair : ICryptographicTechnique<string, string>
	{
		/// <summary>
		/// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
		/// </summary>
		/// <param name="plainText"></param>
		/// <param name="cipherText"></param>
		/// <returns></returns>
		/// 
		public bool check_letter(string text, char letter)
		{
			for (int i = 0; i < text.Length; i++)
			{
				if (letter.Equals(text[i]))
				{

					return true;
				}
			}
			return false;
		}

		public string search(char[,] matrix, char letter)
		{
			for (int i = 0; i < 5; i++)
			{
				for (int j = 0; j < 5; j++)
				{
					if (matrix[i, j] == letter)
					{
						string index = i.ToString();
						index += j.ToString();
						return index;
					}

				}
			}
			return "";
		}

		public string Analyse(string plainText)
		{
			throw new NotImplementedException();
		}

		public string Analyse(string plainText, string cipherText)
		{
			throw new NotSupportedException();
		}

		public string Decrypt(string cipherText, string key)
		{

			string cipherText0 = "";
			for (int counter1 = 0; counter1 < cipherText.Length; counter1++)
			{
				int x = (int)(cipherText[counter1]);
				if (x <= 90)
				{
					x += 32;
				}
				char ch = (char)(x);
				cipherText0 += ch;
			}


			string plainText = "";
			string alphabet = "abcdefghiklmnopqrstuvwxyz";

			char[,] matrix = new char[5, 5];

			string check = "";


			int i = 0;
			int j = 0;
			int c = 0;
			int z = 0;



			for (; ; )
			{
				if (j < 5)
				{
					if (c < key.Length)
					{
						char ch = key[c];
						if (ch == 'j')
						{
							ch = 'i';
						}
						bool found = check_letter(check, ch);
						if (found == false)
						{
							matrix[i, j] = key[c];
							check += key[c];
							c++;
							j++;
						}
						else
						{
							c++;
						}

					}
					else
					{
						if (z < alphabet.Length)
						{
							char ch = alphabet[z];
							bool found = check_letter(check, ch);
							if (found == false)
							{
								matrix[i, j] = alphabet[z];
								check += alphabet[z];
								z++;
								j++;

							}
							else
							{
								z++;
							}
						}
						else
						{
							break;
						}

					}
				}
				else if (i < 5)
				{
					j = 0;
					i++;
				}
				else
				{
					break;
				}
			}



			int p = 0;
			int n = 1;

			for (; ; )
			{
				if (p < cipherText0.Length)
				{
					char ch1 = cipherText0[p];
					if (ch1 == 'j')
					{
						ch1 = 'i';
					}

					char ch2 = 'N';

					if (p == cipherText0.Length - 1)
					{
						ch2 = 'x';
					}
					else
					{
						ch2 = cipherText0[n];
					}

					if (ch2 == 'j')
					{
						ch2 = 'i';
					}

					if (ch1.Equals(ch2))
					{
						ch2 = 'x';
						p += 1;
						n += 1;
					}
					else
					{
						p += 2;
						n += 2;
					}

					string index1 = search(matrix, ch1);
					int ch1_x = (int)Char.GetNumericValue(index1[0]);
					int ch1_y = (int)Char.GetNumericValue(index1[1]);

					string index2 = search(matrix, ch2);
					int ch2_x = (int)Char.GetNumericValue(index2[0]);
					int ch2_y = (int)Char.GetNumericValue(index2[1]);

					//Console.WriteLine("ch1 =>" + ch1 + " i = " + ch1_x + " j = " + ch1_y);
					//Console.WriteLine("ch2 =>" + ch2 + " i = " + ch2_x + " j = " + ch2_y);
					// same row
					if (ch1_x == ch2_x)
					{
						if (ch1_y == 0)
						{
							plainText += matrix[ch1_x, 4];
						}
						else
						{
							plainText += matrix[ch1_x, ch1_y - 1];
						}
						if (ch2_y == 0)
						{
							plainText += matrix[ch2_x, 4];
						}
						else
						{
							plainText += matrix[ch2_x, ch2_y - 1];
						}
					}

					// same column
					else if (ch1_y == ch2_y)
					{
						if (ch1_x == 0)
						{
							plainText += matrix[4, ch1_y];
						}
						else
						{
							plainText += matrix[ch1_x - 1, ch1_y];
						}
						if (ch2_x == 0)
						{
							plainText += matrix[4, ch2_y];
						}
						else
						{
							plainText += matrix[ch2_x - 1, ch2_y];
						}
					}

					// diagonal
					else
					{
						plainText += matrix[ch1_x, ch2_y];
						plainText += matrix[ch2_x, ch1_y];

					}

				}

				else
				{
					break;
				}
			}

			string plainText_lastv = "";

			for (int counter = 0; counter < plainText.Length - 2; counter++)
			{
				int next = counter + 1;
				int last = counter + 2;
				char last_ch = plainText[counter];
				if ((plainText[counter] == plainText[last]) && (plainText[next] == 'x') && counter % 2 == 0)
				{
					counter++;
				}
				plainText_lastv += last_ch;
			}
			if (plainText[plainText.Length - 2] != 'x')
			{
				plainText_lastv += plainText[plainText.Length - 2];
			}
			if (plainText[plainText.Length - 1] != 'x')
			{
				plainText_lastv += plainText[plainText.Length - 1];
			}
			return plainText_lastv;

		}

		public string Encrypt(string plainText, string key)
		{
			string alphabet = "abcdefghiklmnopqrstuvwxyz";
			string cipherText = "";
			char[,] matrix = new char[5, 5];

			string check = "";


			int i = 0;
			int j = 0;
			int c = 0;
			int z = 0;



			for (; ; )
			{
				if (j < 5)
				{
					if (c < key.Length)
					{
						char ch = key[c];
						if (ch == 'j')
						{
							ch = 'i';
						}
						bool found = check_letter(check, ch);
						if (found == false)
						{
							matrix[i, j] = key[c];
							check += key[c];
							c++;
							j++;
						}
						else
						{
							c++;
						}

					}
					else
					{
						if (z < alphabet.Length)
						{
							char ch = alphabet[z];
							bool found = check_letter(check, ch);
							if (found == false)
							{
								matrix[i, j] = alphabet[z];
								check += alphabet[z];
								z++;
								j++;

							}
							else
							{
								z++;
							}
						}
						else
						{
							break;
						}

					}
				}
				else if (i < 5)
				{
					j = 0;
					i++;
				}
				else
				{
					break;
				}
			}


			int p = 0;
			int n = 1;

			for (; ; )
			{
				if (p < plainText.Length)
				{
					char ch1 = plainText[p];
					if (ch1 == 'j')
					{
						ch1 = 'i';
					}

					char ch2 = 'N';

					if (p == plainText.Length - 1)
					{
						ch2 = 'x';
					}
					else
					{
						ch2 = plainText[n];
					}

					if (ch2 == 'j')
					{
						ch2 = 'i';
					}

					if (ch1.Equals(ch2))
					{
						ch2 = 'x';
						p += 1;
						n += 1;
					}
					else
					{
						p += 2;
						n += 2;
					}

					string index1 = search(matrix, ch1);
					int ch1_x = (int)Char.GetNumericValue(index1[0]);
					int ch1_y = (int)Char.GetNumericValue(index1[1]);

					string index2 = search(matrix, ch2);
					int ch2_x = (int)Char.GetNumericValue(index2[0]);
					int ch2_y = (int)Char.GetNumericValue(index2[1]);

					//Console.WriteLine("ch1 =>" + ch1 + " i = " + ch1_x + " j = " + ch1_y);
					//Console.WriteLine("ch2 =>" + ch2 + " i = " + ch2_x + " j = " + ch2_y);
					// same row
					if (ch1_x == ch2_x)
					{
						if (ch1_y == 4)
						{
							cipherText += matrix[ch1_x, 0];
						}
						else
						{
							cipherText += matrix[ch1_x, ch1_y + 1];
						}
						if (ch2_y == 4)
						{
							cipherText += matrix[ch2_x, 0];
						}
						else
						{
							cipherText += matrix[ch2_x, ch2_y + 1];
						}
					}

					// same column
					else if (ch1_y == ch2_y)
					{
						if (ch1_x == 4)
						{
							cipherText += matrix[0, ch1_y];
						}
						else
						{
							cipherText += matrix[ch1_x + 1, ch1_y];
						}
						if (ch2_x == 4)
						{
							cipherText += matrix[0, ch2_y];
						}
						else
						{
							cipherText += matrix[ch2_x + 1, ch2_y];
						}
					}

					// diagonal
					else
					{
						cipherText += matrix[ch1_x, ch2_y];
						cipherText += matrix[ch2_x, ch1_y];

					}

				}

				else
				{
					return cipherText;
				}
			}
		}
	}
}
