using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
	public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
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
			StringBuilder bef_firstApperance = new StringBuilder();
			StringBuilder aft_firstApperance = new StringBuilder();
			int count = 0;
			for (int j = 1; j < key.Length; j++)
			{
				if (key[0] == key[j])
				{
					count = j;
					for (int i = 0; i < count; i++)
					{
						bef_firstApperance.Append(key[i]);
						aft_firstApperance.Append(key[i + count]);
					}
					if (!(bef_firstApperance.Equals(aft_firstApperance)))
					{
						bef_firstApperance.Clear();
						aft_firstApperance.Clear();
						continue;
					}
					else
					{
						break;
					}

				}
			}
			return bef_firstApperance.ToString();
		}

		public string Decrypt(string cipherText, string key)
		{
			StringBuilder plain = new StringBuilder();
			StringBuilder repeatingKey = new StringBuilder(key);
			string cipher = cipherText.ToLower();
			for (int i = 0; i < cipher.Length; i++)
			{
				int calc;
				if (cipher[i] >= repeatingKey[i])
				{
					calc = ((cipher[i] - 'a') - (repeatingKey[i] - 'a')) % 26;
				}
				else
				{
					calc = ((cipher[i] - 'a') - (repeatingKey[i] - 'a')) + 26;
				}
				plain.Append((char)(calc + 97));
				if (repeatingKey.Length != cipher.Length)
				{
					repeatingKey.Append(repeatingKey[i]);
				}
			}
			return plain.ToString();
		}

		public string Encrypt(string plainText, string key)
		{
			StringBuilder repeatingKey = new StringBuilder(key);
			StringBuilder cipher = new StringBuilder();
			string plain = plainText.ToLower();
			for (int i = 0; i < plain.Length; i++)
			{
				int calc = ((plain[i] - 'a') + (repeatingKey[i] - 'a')) % 26;
				cipher.Append((char)(calc + 97));
				if (repeatingKey.Length != plain.Length)
				{
					repeatingKey.Append(repeatingKey[i]);
				}
			}
			return cipher.ToString();
		}
	}
}