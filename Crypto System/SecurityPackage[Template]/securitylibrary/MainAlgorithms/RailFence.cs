using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
			int key = 2;
			int rows = key;
			string cipther2 = cipherText;
			int cols2 = cipther2.Length / key;
			int mod2 = cipther2.Length % key;
			bool putX1 = false;
			bool putX2 = false;

			char[,] plaintext2 = plaintext2 = new char[key, cols2];
			;

			if (mod2 != 0)
			{
				if (mod2 == 1 && key == 3) { mod2++; cols2++; }
				else if (mod2 == 2 && key == 3) { mod2--; cols2++; }
				if (key == 3)
				{
					plaintext2 = new char[key, cols2];
					int count = 0;
					int AddedRows = rows - 1;
					while (count < mod2)
					{
						plaintext2[AddedRows, cols2 - 1] = 'x';
						count++;
						AddedRows--;
					}
					putX2 = true;

				}
				if (key == 2)
				{
					cols2++;
					plaintext2 = new char[key, cols2];

					for (int i = 0; i < mod2; i++)
					{
						cipther2 += 'x';
						putX1 = true;

					}
				}
			}


			int index2 = 0;
			for (int i = 0; i < key; i++)
			{
				for (int j = 0; j < cols2; j++)
				{
					if (plaintext2[i, j] == 'x') continue;
					plaintext2[i, j] = cipther2[index2];
					index2++;
				}
				if (index2 == cipther2.Length)
					break;
			}
			string plainTextRes = string.Empty;

			for (int i = 0; i < cols2; i++)
			{
				for (int j = 0; j < rows; j++)
				{
					plainTextRes += plaintext2[j, i];
				}
			}
			if (putX1) { plainTextRes = plainTextRes.Remove((plainTextRes.Length - 1), 1); }
			if (putX2)
			{
				plainTextRes = plainTextRes.Remove((plainTextRes.Length - 2), 2);
			}

			plainTextRes = plainTextRes.ToLower();
			if (plainTextRes == plainText.ToLower())
				return key;

			return (key + 1);
		}

        public string Decrypt(string cipherText, int key)
        {
			int rows = key;
			string cipther2 = cipherText;
			int cols2 = cipther2.Length / key;
			int mod2 = cipther2.Length % key;
			bool putX1 = false;
			bool putX2 = false;

			char[,] plaintext2 = plaintext2 = new char[key, cols2];
			;

			if (mod2 != 0)
			{
				if (mod2 == 1 && key == 3) { mod2++; cols2++; }
				else if (mod2 == 2 && key == 3) { mod2--; cols2++; }
				if (key == 3)
				{
					plaintext2 = new char[key, cols2];
					int count = 0;
					int AddedRows = rows - 1;
					while (count < mod2)
					{
						plaintext2[AddedRows, cols2 - 1] = 'x';
						count++;
						AddedRows--;
					}
					putX2 = true;

				}
				if (key == 2)
				{
					cols2++;
					plaintext2 = new char[key, cols2];

					for (int i = 0; i < mod2; i++)
					{
						cipther2 += 'x';
						putX1 = true;

					}
				}
			}


			int index2 = 0;
			for (int i = 0; i < key; i++)
			{
				for (int j = 0; j < cols2; j++)
				{
					if (plaintext2[i, j] == 'x') continue;
					plaintext2[i, j] = cipther2[index2];
					index2++;
				}
				if (index2 == cipther2.Length)
					break;
			}
			string plainTextRes = string.Empty;

			for (int i = 0; i < cols2; i++)
			{
				for (int j = 0; j < rows; j++)
				{
					plainTextRes += plaintext2[j, i];
				}
			}
			if (putX1) { plainTextRes = plainTextRes.Remove((plainTextRes.Length - 1), 1); }
			if (putX2)
			{
				plainTextRes = plainTextRes.Remove((plainTextRes.Length - 2), 2);
			}

			plainTextRes = plainTextRes.ToLower();
			return plainTextRes;
		}

        public string Encrypt(string plainText, int key)
        {

			plainText = plainText.Replace(" ", "");
			int rows = key;
			bool hasX = false;
			int mod = plainText.Length % key;
			if (plainText.Length % key != 0)
			{
				if (mod == 1 && key == 3) mod++;
				else if (mod == 2 && key == 3) mod--;
				for (int i = 0; i < mod; i++)
				{
					plainText += 'x';
				}
				hasX = true;
			}

			int cols = plainText.Length / key;

			int index = 0;

			char[,] cipherMatrix = new char[rows, cols];

			for (int i = 0; i < cols; i++)
			{
				for (int j = 0; j < rows; j++)
				{
					cipherMatrix[j, i] = plainText[index];
					index++;
				}
				if (index == plainText.Length)
					break;
			}
			if (hasX)
			{
				int count = 0;
				int deleteRow = rows - 1;
				while (count < mod)
				{
					cipherMatrix[deleteRow, cols - 1] = char.Parse(" ");
					count++;
					deleteRow--;
				}
			}
			string cipher = string.Empty;
			for (int i = 0; i < rows; i++)
			{
				for (int j = 0; j < cols; j++)
				{
					cipher += cipherMatrix[i, j];
				}

			}
			cipher = cipher.ToUpper();
			if (hasX) cipher = cipher.Replace(" ", "");

			return cipher;
		}
	}
}
