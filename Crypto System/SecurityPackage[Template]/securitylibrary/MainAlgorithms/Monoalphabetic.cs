using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
	public class Monoalphabetic : ICryptographicTechnique<string, string>
	{
		public string Analyse(string plainText, string cipherText)
		{
			StringBuilder initKey = new StringBuilder("abcdefghijklmnopqrstuvwxyz");
			for (int i = 0; i < cipherText.Length; i++)
			{
				initKey[(int)plainText[i] - 97] = cipherText[i];
			}
			StringBuilder finalKey = new StringBuilder(initKey.ToString());
			char found = 'A';
			for (int i = 0; i < finalKey.Length; i++)
			{
				if (finalKey[i] >= 'a' && finalKey[i] <= 'z')
				{
					for (char upperCase = 'A'; upperCase <= 'Z'; upperCase++)
					{
						if (!finalKey.ToString().Contains(upperCase))
						{
							found = upperCase;
							break;
						}
					}
					finalKey[i] = found;
				}
			}
			return finalKey.ToString().ToLower();
		}

		public string Decrypt(string cipherText, string key)
		{
			StringBuilder plain = new StringBuilder();
			for (int i = 0; i < cipherText.Length; i++)
				for (int j = 0; j < key.Length; j++)
					if (cipherText[i] + 32 == key[j])
						plain.Append((char)(j + 97));
			return plain.ToString();

		}

		public string Encrypt(string plainText, string key)
		{
			StringBuilder cipher = new StringBuilder();
			for (int i = 0; i < plainText.Length; i++)
				cipher.Append(key[(int)plainText[i] - 97]);
			return cipher.ToString();
		}

		/// <summary>
		/// Frequency Information:
		/// E   12.51%
		/// T	9.25
		/// A	8.04
		/// O	7.60
		/// I	7.26
		/// N	7.09
		/// S	6.54
		/// R	6.12
		/// H	5.49
		/// L	4.14
		/// D	3.99
		/// C	3.06
		/// U	2.71
		/// M	2.53
		/// F	2.30
		/// P	2.00
		/// G	1.96
		/// W	1.92
		/// Y	1.73
		/// B	1.54
		/// V	0.99
		/// K	0.67
		/// X	0.19
		/// J	0.16
		/// Q	0.11
		/// Z	0.09
		/// </summary>
		/// <param name="cipher"></param>
		/// <returns>Plain text</returns>
		public string AnalyseUsingCharFrequency(string cipher)
		{
			Dictionary<char, int> dict = new Dictionary<char, int>();
			for (int i = 0; i < cipher.Length; i++)
			{
				bool isFound = false;
				foreach (var pair in dict)
				{
					if (cipher[i] == pair.Key)
					{
						dict[cipher[i]]++;
						isFound = true;
						break;
					}
				}
				if (!isFound)
				{
					dict[cipher[i]] = 1;
				}
			}
			var descDict = dict.OrderByDescending(x => x.Value);
			char[] key = { 'E', 'T', 'A', 'O', 'I', 'N', 'S', 'R', 'H', 'L', 'D', 'C', 'U', 'M', 'F', 'P', 'G', 'W', 'Y', 'B', 'V', 'K', 'X', 'J', 'Q', 'Z' };
			StringBuilder plain = new StringBuilder();
			for (int i = 0; i < cipher.Length; i++)
			{
				int j = 0;
				foreach (var pair in descDict)
				{
					if (cipher[i] == pair.Key && j < 26)
					{
						plain.Append(key[j]);
					}
					j++;
				}
			}
			return plain.ToString().ToLower();
		}
	}
}