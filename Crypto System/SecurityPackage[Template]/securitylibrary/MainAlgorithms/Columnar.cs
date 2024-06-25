using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
			int keyCount = 2;

			for (int i = 2; i < 10; i++)
			{
				if (plainText.Length % i == 0)
				{ keyCount = i; break; }
			}

			int rows = plainText.Length / keyCount;
			int cols = keyCount;

			char[,] plain = new char[cols, rows];

			int indexForPlain = 0;
			for (int i = 0; i < cols; i++)
			{
				for (int j = 0; j < rows; j++)
				{
					plain[i, j] = plainText.ElementAt(indexForPlain);
					indexForPlain++;
				}
			}
			string[] arrPlain = new string[rows];
			for (int i = 0; i < rows; i++)
			{

				StringBuilder sb = new StringBuilder();
				for (int j = 0; j < keyCount; j++)
				{
					sb.Append(plain[j, i]);
				}
				arrPlain[i] = sb.ToString();

			}

			string[] arrCipther = new string[rows];
			int ciptherIndex = 0;
			for (int i = 0; i < rows; i++)
			{
				arrCipther[i] = cipherText.Substring(ciptherIndex, keyCount);
				ciptherIndex += 3;
			}

			int move = 0;
			int[] arrIndex = new int[rows];
			int key = 1;
			for (int i = 0; i < rows; i++)
			{
				if (arrCipther[move].ToLower() == arrPlain[i])
				{ arrIndex[i] = key; move++; i = 0; key++; }
				if (move == rows)
					break;
			}
			List<int> Key = new List<int>();
			foreach (var item in arrIndex)
			{
				Key.Add(item);
			}
			return Key;
		}

        public string Decrypt(string cipherText, List<int> key)
        {

			int rows2 = cipherText.Length / key.Count;
			int cols2 = key.Count;
			int NumberofX = key.Count - (cipherText.Length - (key.Count * rows2));
			bool putX = false;
			if (cipherText.Length % key.Count != 0)
			{ rows2++; putX = true; }

			char[,] plainText2 = new char[rows2, cols2];
			for (int i = rows2 - 1; i < rows2; i++)
			{
				for (int j = NumberofX + 1; j < cols2; j++)
				{
					plainText2[i, j] = ' ';
				}
			}

			int vlaue2 = 1;
			int KeyIndex2 = 0;
			int ArrayIndex = 0;
			for (; ; )
			{
				int i = 0;
				if (vlaue2 > key.Count)
					break;
				for (int x = 0; x < key.Count; x++)
				{
					if (key[x] == vlaue2)
					{ i = x; vlaue2++; break; }
				}
				for (int j = 0; j < rows2; j++)
				{
					if (plainText2[j, i] == ' ')
					{ continue; }
					else
					{
						plainText2[j, i] = cipherText.ElementAt(ArrayIndex);
						ArrayIndex++;
					}
				}
			}

			string plain = string.Empty;
			for (int i = 0; i < rows2; i++)
			{
				for (int j = 0; j < cols2; j++)
				{
					plain += plainText2[i, j];
				}
			}
			plain = plain.Replace(" ", "");
			plain = plain.ToLower();
			return plain;
		}

        public string Encrypt(string plainText, List<int> key)
        {
			int rows = plainText.Length / key.Count;
			int cols = key.Count;
			bool hasX = false;
			if (plainText.Length % key.Count != 0)
			{ rows++; hasX = true; }

			char[,] cipther = new char[rows, cols];

			int index = 0;
			for (int i = 0; i < rows; i++)
			{
				for (int j = 0; j < cols; j++)
				{
					if (index == plainText.Length && j < cols)
					{ cipther[i, j] = ' '; }
					else
					{
						cipther[i, j] = plainText.ElementAt(index);
						index++;
					}

				}
			}

			int value = 1;
			string ciptherText = string.Empty;
			for (; ; )
			{
				int i = 0;
				if (value > key.Count)
					break;
				for (int x = 0; x < key.Count; x++)
				{
					if (key[x] == value)
					{ i = x; value++; break; }
				}
				for (int j = 0; j < rows; j++)
				{
					ciptherText += cipther[j, i];
				}

			}
			ciptherText = ciptherText.Replace(" ", "");
			ciptherText = ciptherText.ToUpper();
			return ciptherText;
		}
    }
}
