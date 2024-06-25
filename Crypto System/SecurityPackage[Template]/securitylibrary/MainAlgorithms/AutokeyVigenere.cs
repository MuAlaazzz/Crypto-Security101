using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
	public class AutokeyVigenere : ICryptographicTechnique<string, string>
	{
		public string Analyse(string plainText, string cipherText)
		{
			StringBuilder key = new StringBuilder();
			string plain = plainText.ToLower();
			string cipher = cipherText.ToLower();

			for (int i = 0; i < cipher.Length; i++)
			{
				int calc;
				if (cipher[i] >= plain[i])
				{
					calc = ((cipher[i] - 'a') - (plain[i] - 'a')) % 26;
				}
				else
				{
					calc = ((cipher[i] - 'a') - (plain[i] - 'a')) + 26;
				}
				key.Append((char)(calc + 97));
			}
			Console.WriteLine(key.ToString());
			string addedPlain = "";
			StringBuilder originalKey = new StringBuilder();
			int count = 0;
			for (int j = 1; j < key.Length; j++)
			{
				if (key[j] == plain[0])
				{
					count = j;
					for (int i = count; i < key.Length; i++)
					{
						addedPlain += key[i];
						if (i - count < count)
						{
							originalKey.Append(key[i - count]);
						}

					}
					if (!(plain.Contains(addedPlain)))
					{

						addedPlain = "";
						originalKey.Clear();
					}
					else
					{
						break;
					}
				}
			}
			Console.WriteLine(addedPlain);
			Console.WriteLine(originalKey.ToString());
			return originalKey.ToString();

		}

		public string Decrypt(string cipherText, string key)
		{

			StringBuilder plain = new StringBuilder();
			StringBuilder autoKey = new StringBuilder(key);
			string cipher = cipherText.ToLower();
			for (int i = 0; i < cipher.Length; i++)
			{
				int calc;
				if (cipher[i] >= autoKey[i])
				{
					calc = ((cipher[i] - 'a') - (autoKey[i] - 'a')) % 26;
				}
				else
				{
					calc = ((cipher[i] - 'a') - (autoKey[i] - 'a')) + 26;
				}
				plain.Append((char)(calc + 97));
				if (autoKey.Length != cipher.Length)
				{
					autoKey.Append(plain[i]);
				}
			}
			return plain.ToString();
		}

		public string Encrypt(string plainText, string key)
		{
			StringBuilder autoKey = new StringBuilder(key);
			StringBuilder cipher = new StringBuilder();
			string plain = plainText.ToLower();
			for (int i = 0; i < plain.Length; i++)
			{
				int calc = ((plain[i] - 'a') + (autoKey[i] - 'a')) % 26;
				cipher.Append((char)(calc + 97));
				if (autoKey.Length != plain.Length)
				{
					autoKey.Append(plain[i]);
				}
			}
			return cipher.ToString();
		}
	}
}