using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{

	public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
	{

		public static int[,] createMatrix(List<int> list, int rows, int columns)
		{
			int[,] matrix = new int[rows, columns];
			int counter = 0;
			for (int i = 0; i < columns; i++)
			{
				for (int j = 0; j < rows; j++)
				{
					matrix[j, i] = list[counter];
					counter++;
				}
			}

			return matrix;
		}

		public static int[,] createKey(List<int> list, int rows, int columns)
		{
			int[,] matrix = new int[rows, columns];
			int counter = 0;
			for (int i = 0; i < rows; i++)
			{
				for (int j = 0; j < columns; j++)
				{
					matrix[i, j] = list[counter];
					counter++;
				}
			}

			return matrix;
		}

		public static void printMatrix(int[,] t, int rows, int columns)
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

		public static List<int> createList(int[,] matrix, int rows, int columns)
		{
			List<int> list = new List<int>();
			int counter = 0;
			for (int i = 0; i < columns; i++)
			{
				for (int j = 0; j < rows; j++)
				{

					list.Add(matrix[j, i]);
					counter++;
				}
			}
			return list;
		}


		public static bool check_key(int[,] matrix, int rows, int columns)
		{

			for (int i = 0; i < rows; i++)
			{
				for (int j = 0; j < columns; j++)
				{
					int x = (int)(matrix[i, j]);
					if ((matrix[i, j] < 0) && (matrix[i, j] % 26 != 0) && (x != matrix[i, j]))
					{
						return false;
					}
				}
			}

			return true;
		}

		public static int subMatrixMultiplication(int[,] matrix, int rows, int columns, int r, int c)
		{
			int[,] subMatrix = new int[2, 2];
			int counterRow = 0;

			for (int i = 0; i < rows; i++)
			{
				int counterColumn = 0;
				if (i == r)
				{
					continue;
				}
				for (int j = 0; j < columns; j++)
				{
					if (j == c)
					{
						continue;
					}
					else
					{
						subMatrix[counterRow, counterColumn] = matrix[i, j];
						counterColumn++;
					}
				}
				counterRow++;
			}

			int x = (subMatrix[0, 0] * subMatrix[1, 1]) - (subMatrix[1, 0] * subMatrix[0, 1]);

			return x;
		}

		public static int findDet(int[,] matrix, int c1, int c2)
		{

			int[,] subMatrix = new int[2, 2];

			subMatrix[0, 0] = matrix[0, c1];
			subMatrix[0, 1] = matrix[1, c1];
			subMatrix[1, 0] = matrix[0, c2];
			subMatrix[1, 1] = matrix[1, c2];


			int det = (subMatrix[0, 0] * subMatrix[1, 1]) - (subMatrix[0, 1] * subMatrix[1, 0]);

			if (det < 0)
			{
				while (det < 0)
				{
					det += 26;
				}
			}
			else if (det > 25)
			{
				det %= 26;
			}



			return det;
		}

		public static int GCD(int a, int b)
		{
			if (b == 0)
			{
				return a;
			}
			else
			{
				return GCD(b, a % b);
			}
		}


		public List<int> Analyse(List<int> plainText, List<int> cipherText)
		{
			int m = 2;

			List<int> key = new List<int> { };

			int cipher_size = cipherText.Count;


			int blocks = cipher_size / m;

			// convert plain from list to matrix

			int[,] cipherMatrix = createMatrix(cipherText, m, blocks);

			// convert key from list to matrix

			int[,] plainMatrix = createMatrix(plainText, m, blocks);


			// find the det(plain)

			int c1 = 0;
			int c2 = 0;
			int det = 0;
			int check0 = 0;
			for (int i = 0; i < blocks; i++)
			{
				for (int j = 0; j < blocks; j++)
				{
					int d = findDet(plainMatrix, i, j);
					int check = GCD(26, d);
					if (check == 1)
					{
						c1 = i;
						c2 = j;
						det = d;
						check0 = 1;
					}
				}
			}

			//Console.WriteLine(check0 + " " + det + " " + c1 + " " + c2);
			// find b = invers det(plain)

			//calaulate b = inverse det(k) 

			// the main rule is : (26 - c)(26 - (26-det(k) )) mod 26 = 1 ,But we will use (26-det(k)) * c direct.
			// because always : 26 power 2 mod 26 = 0 , 26 * (any num) mod 26 = 0 , c * (any num) mod 26 = 0

			int b = 0;
			float a = (float)(26 - det);
			int y = 1;
			int C = 0;

			// a * c mod 26 = y
			// ex : 3 * c mod 26 = 1 

			while (true)
			{
				float resFloat = y / a;
				int resInt = (int)resFloat;
				if (resFloat == resInt)
				{
					C = resInt;
					break;
				}
				else
				{
					y += 26;
				}
			}


			b = 26 - C;



			if (check0 == 1)
			{
				// find inverse plain

				int[,] pm = new int[2, 2];
				int[,] plainMatrixInverse = new int[2, 2];

				pm[0, 0] = plainMatrix[0, c1];
				pm[1, 0] = plainMatrix[1, c1];
				pm[0, 1] = plainMatrix[0, c2];
				pm[1, 1] = plainMatrix[1, c2];

				plainMatrixInverse[0, 0] = b * pm[1, 1];
				plainMatrixInverse[0, 1] = b * -pm[0, 1];
				plainMatrixInverse[1, 0] = b * -pm[1, 0];
				plainMatrixInverse[1, 1] = b * pm[0, 0];

				for (int i = 0; i < 2; i++)
				{
					for (int j = 0; j < 2; j++)
					{
						if (plainMatrixInverse[i, j] > 25)
						{
							plainMatrixInverse[i, j] = plainMatrixInverse[i, j] % 26;
						}
						else if (plainMatrixInverse[i, j] < 0)
						{
							while (plainMatrixInverse[i, j] < 0)
							{
								plainMatrixInverse[i, j] += 26;
							}
						}
					}
				}

				printMatrix(plainMatrixInverse, 2, 2);



				// matrix Multiplication

				int[,] matrix2 = new int[m, m];
				for (int i = 0; i < m; i++)
				{
					for (int j = 0; j < m; j++)
					{
						int sum = 0;
						for (int c = 0; c < m; c++)
						{
							sum += cipherMatrix[i, c] * plainMatrixInverse[c, j];
						}
						if (sum > 25)
						{
							sum %= 26;
						}
						Console.WriteLine(sum);
						matrix2[i, j] = sum;

					}
				}
				key = createList(matrix2, m, m);
			}
			else
			{
				throw new NotImplementedException();
			}

			return key;

		}
		public string Analyse(string plainText, string cipherText)
		{
			throw new NotImplementedException();
		}

		public List<int> Decrypt(List<int> cipherText, List<int> key)
		{

			List<int> plain = new List<int> { };

			int cipher_size = cipherText.Count;
			int key_size = key.Count;

			int m = 0;

			if (key_size == 4)
			{
				m = 2;
			}
			else if (key_size == 9)
			{
				m = 3;
			}

			int blocks = cipher_size / m;

			// convert plain from list to matrix

			int[,] cipherMatrix = createMatrix(cipherText, m, blocks);

			// convert key from list to matrix

			int[,] keyMatrix = createKey(key, m, m);


			// find inverse key 

			// key 2By2
			if (m == 2)
			{
				int[,] km = createKey(key, m, m);

				if (m == 2)
				{
					int k = (keyMatrix[0, 0] * keyMatrix[1, 1]) - (keyMatrix[0, 1] * keyMatrix[1, 0]);
					int det = k;

					if (det < 0)
					{
						while (det < 0)
						{
							det += 26;
						}
					}
					else if (det > 25)
					{
						det %= 26;
					}

					int check_GCD = GCD(26, det);

					if ((check_GCD == 1) && (det != 0))
					{
						k = 1 / k;

						keyMatrix[0, 0] = k * km[1, 1];
						keyMatrix[0, 1] = k * -km[0, 1];
						keyMatrix[1, 0] = k * -km[1, 0];
						keyMatrix[1, 1] = k * km[0, 0];

						for (int i = 0; i < 2; i++)
						{
							for (int j = 0; j < 2; j++)
							{
								if (keyMatrix[i, j] > 25)
								{
									keyMatrix[i, j] = keyMatrix[i, j] % 26;
								}
								else if (keyMatrix[i, j] < 0)
								{
									while (keyMatrix[i, j] < 0)
									{
										keyMatrix[i, j] += 26;
									}
								}
							}
						}

						// decryption

						int[,] matrix2 = new int[m, blocks];

						int x = 0;
						for (int j = 0; j < blocks; j++)
						{
							for (int i = 0; i < m; i++)
							{
								int sum = 0;
								for (int c = 0; c < m; c++)
								{

									sum += keyMatrix[x, c] * cipherMatrix[c, j];

								}
								if (sum > 25)
								{
									sum = sum % 26;
								}
								if (m == 2)
								{
									x = (x == 0 ? 1 : 0);
								}
								else
								{
									if (x == 0)
									{
										x = 1;
									}
									else if (x == 1)
									{
										x = 2;
									}
									else
									{
										x = 0;
									}
								}

								//Console.WriteLine(sum);
								matrix2[i, j] = sum;
							}
						}
						plain = createList(matrix2, m, blocks);
					}
					else
					{
						throw new NotImplementedException();
					}

				}
			}

			// key 3By3
			else if (m == 3)
			{
				//calaulate det(k)
				int det = (keyMatrix[0, 0] * subMatrixMultiplication(keyMatrix, m, m, 0, 0))
					- (keyMatrix[0, 1] * subMatrixMultiplication(keyMatrix, m, m, 0, 1))
					+ (keyMatrix[0, 2] * subMatrixMultiplication(keyMatrix, m, m, 0, 2));

				if (det < 0)
				{
					while (det < 0)
					{
						det += 26;
					}
				}
				else
				{
					det %= 26;
				}

				int check_GCD = GCD(26, det);

				if ((check_GCD == 1) && (det != 0))
				{
					//calaulate b = inverse det(k) 

					// the main rule is : (26 - c)(26 - (26-det(k) )) mod 26 = 1 ,But we will use (26-det(k)) * c direct.
					// because always : 26 power 2 mod 26 = 0 , 26 * (any num) mod 26 = 0 , c * (any num) mod 26 = 0

					int b = 0;
					float a = (float)(26 - det);
					int y = 1;
					int C = 0;

					// a * c mod 26 = y
					// ex : 3 * c mod 26 = 1 

					while (true)
					{
						float resFloat = y / a;
						int resInt = (int)resFloat;
						if (resFloat == resInt)
						{
							C = resInt;
							break;
						}
						else
						{
							y += 26;
						}
					}


					b = 26 - C;

					//find inverse key
					int[,] keyInverse = new int[3, 3];

					for (int i = 0; i < m; i++)
					{
						for (int j = 0; j < m; j++)
						{
							int var = 0;
							int res = 0;
							if ((i + j) % 2 == 0)
							{
								var = b;
							}
							else
							{
								var = -b;
							}
							res = var * subMatrixMultiplication(keyMatrix, m, m, i, j);
							if (res < 0)
							{
								while (res < 0)
								{
									res += 26;
								}
							}
							else
							{
								res %= 26;
							}

							keyInverse[j, i] = res;

						}
					}

					//decryption

					int[,] matrix2 = new int[m, blocks];

					int x = 0;
					for (int j = 0; j < blocks; j++)
					{
						for (int i = 0; i < m; i++)
						{
							int sum = 0;
							for (int c = 0; c < m; c++)
							{

								sum += keyInverse[x, c] * cipherMatrix[c, j];

							}
							if (sum > 25)
							{
								sum = sum % 26;
							}
							if (m == 2)
							{
								x = (x == 0 ? 1 : 0);
							}
							else
							{
								if (x == 0)
								{
									x = 1;
								}
								else if (x == 1)
								{
									x = 2;
								}
								else
								{
									x = 0;
								}
							}

							Console.WriteLine(sum);
							matrix2[i, j] = sum;
						}
					}

					plain = createList(matrix2, m, blocks);
				}
				else
				{
					throw new NotImplementedException();
				}
			}
			return plain;
		}

		public string Decrypt(string cipherText, string key)
		{
			throw new NotImplementedException();
		}


		public List<int> Encrypt(List<int> plainText, List<int> key)
		{
			// input

			int plain_size = plainText.Count;
			int key_size = key.Count;

			int m = 0;

			if (key_size == 4)
			{
				m = 2;
			}
			else if (key_size == 9)
			{
				m = 3;
			}




			int blocks = plain_size / m;

			// convert plain from list to matrix

			int[,] plainMatrix = createMatrix(plainText, m, blocks);

			// convert key from list to matrix

			int[,] keyMatrix = createKey(key, m, m);

			// encryption

			int[,] matrix2 = new int[m, blocks];

			int x = 0;
			for (int j = 0; j < blocks; j++)
			{
				for (int i = 0; i < m; i++)
				{
					int sum = 0;
					for (int c = 0; c < m; c++)
					{

						sum += keyMatrix[x, c] * plainMatrix[c, j];
					}
					if (sum > 25)
					{
						sum = sum % 26;
					}
					if (m == 2)
					{
						x = (x == 0 ? 1 : 0);
					}
					else
					{
						if (x == 0)
						{
							x = 1;
						}
						else if (x == 1)
						{
							x = 2;
						}
						else
						{
							x = 0;
						}
					}
					matrix2[i, j] = sum;
				}
			}

			//printMatrix(matrix2, m, blocks);

			List<int> cipher = createList(matrix2, m, blocks);

			return cipher;
		}

		public string Encrypt(string plainText, string key)
		{
			throw new NotImplementedException();
		}


		public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
		{

			List<int> key = new List<int> { };

			//List<int> key4 = new List<int> { 1, 10, 0, 0, 20, 1, 2, 15, 2 };

			//{3 ,7 ,18 ,14 ,6 ,23 ,12 ,3 ,15};


			//List<int> key;

			int cipher_size = cipher3.Count;
			int plain_size = plain3.Count;

			int m = 3;



			int blocks = cipher_size / m;

			// convert plain from list to matrix

			int[,] cipherMatrix = createMatrix(cipher3, m, blocks);

			// convert key from list to matrix

			int[,] plainMatrix = createMatrix(plain3, m, m);


			// find inverse key 


			// key 3By3
			//check error
			//calaulate det(k)
			int det = (plainMatrix[0, 0] * subMatrixMultiplication(plainMatrix, m, m, 0, 0))
				- (plainMatrix[0, 1] * subMatrixMultiplication(plainMatrix, m, m, 0, 1))
				+ (plainMatrix[0, 2] * subMatrixMultiplication(plainMatrix, m, m, 0, 2));


			if (det < 0)
			{
				while (det < 0)
				{
					det += 26;
				}
			}
			else
			{
				det %= 26;
			}

			int check_GCD = GCD(26, det);

			if ((check_GCD == 1) && (det != 0))
			{
				//calaulate b = inverse det(k) 

				// the main rule is : (26 - c)(26 - (26-det(k) )) mod 26 = 1 ,But we will use (26-det(k)) * c direct.
				// because always : 26 power 2 mod 26 = 0 , 26 * (any num) mod 26 = 0 , c * (any num) mod 26 = 0


				int b = 0;
				float a = (float)(26 - det);
				int y = 1;
				int C = 0;

				// a * c mod 26 = y
				// ex : 3 * c mod 26 = 1 

				while (true)
				{
					float resFloat = y / a;
					int resInt = (int)resFloat;
					if (resFloat == resInt)
					{
						C = resInt;
						break;
					}
					else
					{
						y += 26;
					}
				}


				b = 26 - C;

				//find inverse plain
				int[,] plainMatrixInverse = new int[3, 3];

				for (int i = 0; i < m; i++)
				{
					for (int j = 0; j < m; j++)
					{
						int var = 0;
						int res = 0;
						if ((i + j) % 2 == 0)
						{
							var = b;
						}
						else
						{
							var = -b;
						}
						res = var * subMatrixMultiplication(plainMatrix, m, m, i, j);
						if (res < 0)
						{
							while (res < 0)
							{
								res += 26;
							}
						}
						else
						{
							res %= 26;
						}

						plainMatrixInverse[j, i] = res;

					}
				}
				//printMatrix(keyInverse, m, m);

				//decryption

				int[,] matrix2 = new int[m, blocks];

				for (int i = 0; i < m; i++)
				{
					for (int j = 0; j < m; j++)
					{
						int sum = 0;
						for (int c = 0; c < m; c++)
						{
							sum += cipherMatrix[i, c] * plainMatrixInverse[c, j];
						}
						if (sum > 25)
						{
							sum %= 26;
						}

						matrix2[j, i] = sum;

					}
				}
				key = createList(matrix2, m, blocks);

				return key;
			}
			else
			{
				throw new NotImplementedException();
			}



		}

		public string Analyse3By3Key(string plain3, string cipher3)
		{
			throw new NotImplementedException();
		}
	}
}

