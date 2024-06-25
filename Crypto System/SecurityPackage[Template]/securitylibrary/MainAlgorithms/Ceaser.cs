using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
	public class Ceaser : ICryptographicTechnique<string, int>
	{
		public string Encrypt(string plainText, int key)
		{
			string cipherText = "";
			for (int i = 0; i < plainText.Length; i++)
			{
				int x = (int)(plainText[i] - 'a');
				x += key;
				if (x > 25)
				{
					x -= 26;
				}

				char ch = (char)(x + 97);
				cipherText += ch;
			}
			return cipherText;
		}

		public string Decrypt(string cipherText, int key)
		{
			string plainText = "";
			string cipherText0 = "";
			for (int i = 0; i < cipherText.Length; i++)
			{
				int x = (int)(cipherText[i]);
				if (x <= 90)
				{
					x += 32;
				}
				char ch = (char)(x);
				cipherText0 += ch;
			}

			for (int i = 0; i < cipherText0.Length; i++)
			{

				int x = (int)(cipherText0[i] - 'a');
				x -= key;
				if (x < 0)
				{
					x += 26;
				}
				char ch = (char)(x + 97);
				plainText += ch;
			}
			return plainText;
		}

		public int Analyse(string plainText, string cipherText)
		{
			string cipherText0 = "";
			for (int i = 0; i < cipherText.Length; i++)
			{
				int x = (int)(cipherText[i]);
				if (x <= 90)
				{
					x += 32;
				}
				char ch = (char)(x);
				cipherText0 += ch;
			}
			string plainText0 = "";
			for (int i = 0; i < plainText.Length; i++)
			{
				int x = (int)(plainText[i]);
				if (x <= 90)
				{
					x += 32;
				}
				char ch = (char)(x);
				plainText0 += ch;
			}
			int x1 = (int)(plainText0[0] - 'a');
			int y1 = (int)(cipherText0[0] - 'a');
			int key = y1 - x1;
			if (key < 0)
			{
				key += 26;
			}
			return key;
		}
	}
}
